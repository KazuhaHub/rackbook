package localauth

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
)

// Aggregated events (docs/design-local-accounts.md, 10): per bucket and minute the first login_refused of each
// account, and of unknown accounts, is written in full; the rest is written once at the end of the minute as the
// same event with code summary. Beyond 100 buckets in one minute the rest fold into one summary without addr. The
// audit log is kept forever, and an attacker's refusals must not fill it.
const maxAggBuckets = 100

type bucketAgg struct {
	addr     string
	seen     map[string]bool // accounts (or "") whose first refusal went out in full
	count    int
	reasons  map[string]int
	accounts map[string]bool
	from, to time.Time
}

type aggregator struct {
	mu     sync.Mutex
	event  string
	minute int64
	by     map[string]*bucketAgg
	folded *bucketAgg // buckets past the 100th
	record func(audit.Event)
}

func newAggregator(event string, record func(audit.Event)) *aggregator {
	return &aggregator{event: event, record: record, by: map[string]*bucketAgg{}}
}

// Note counts a refusal. It returns true when this one is to be written in full (the first of its account in
// this bucket this minute), and false when it was counted for the summary.
func (a *aggregator) Note(now time.Time, bucket, addr, account, reason string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := now.Unix() / 60
	var out []audit.Event
	if m != a.minute {
		out = a.drain()
		a.minute = m
	}
	b := a.by[bucket]
	if b == nil {
		if len(a.by) >= maxAggBuckets {
			if a.folded == nil {
				a.folded = &bucketAgg{seen: map[string]bool{}, reasons: map[string]int{}, accounts: map[string]bool{}}
			}
			b = a.folded
		} else {
			b = &bucketAgg{addr: addr, seen: map[string]bool{}, reasons: map[string]int{}, accounts: map[string]bool{}}
			a.by[bucket] = b
		}
	}
	full := b != a.folded && !b.seen[account]
	if full {
		b.seen[account] = true
	} else {
		b.count++
		b.reasons[reason]++
		if account != "" {
			b.accounts[account] = true
		}
		if b.from.IsZero() || now.Before(b.from) {
			b.from = now
		}
		if now.After(b.to) {
			b.to = now
		}
	}
	for _, e := range out {
		a.record(e)
	}
	return full
}

// Flush writes the summaries of the minutes that are over (the clock moved on) or, with all, of every one.
func (a *aggregator) Flush(now time.Time, all bool) {
	a.mu.Lock()
	var out []audit.Event
	if all || now.Unix()/60 != a.minute {
		out = a.drain()
	}
	a.mu.Unlock()
	for _, e := range out {
		a.record(e)
	}
}

// drain makes the summary events of the minute and empties it. The caller holds the lock.
func (a *aggregator) drain() []audit.Event {
	var out []audit.Event
	keys := make([]string, 0, len(a.by))
	for k := range a.by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if e, ok := a.summary(a.by[k], a.by[k].addr); ok {
			out = append(out, e)
		}
	}
	if a.folded != nil {
		if e, ok := a.summary(a.folded, ""); ok {
			out = append(out, e)
		}
	}
	a.by, a.folded = map[string]*bucketAgg{}, nil
	return out
}

func (a *aggregator) summary(b *bucketAgg, addr string) (audit.Event, bool) {
	if b.count == 0 {
		return audit.Event{}, false
	}
	var rs []string
	for r, n := range b.reasons {
		rs = append(rs, r+"="+strconv.Itoa(n))
	}
	slices.Sort(rs)
	return audit.Event{
		Event: a.event, Method: "local", Addr: addr, Code: "summary",
		Detail: []string{
			fmt.Sprintf("count:%d", b.count), "reasons:" + strings.Join(rs, ","), fmt.Sprintf("accounts:%d", len(b.accounts)),
			"from:" + b.from.UTC().Format(time.RFC3339), "to:" + b.to.UTC().Format(time.RFC3339),
		},
	}, true
}
