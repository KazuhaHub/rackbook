package localauth

import (
	"math/rand/v2"
	"sync"
	"time"
)

// The dummy-hash budget (docs/design-local-accounts.md, 8.6): at most 60 dummy argon2id runs a minute for the
// server and 2 a minute per bucket. Past either limit an unknown or non-active name is answered after sleeping a
// duration drawn from the hash-only sample, after the queue wait of this moment, instead of hashing.
const (
	dummyPerMinute       = 60
	dummyPerBucketMinute = 2
	sampleSize           = 256
	samplePerSource      = 16
	sampleReady          = 16
	calibrationRuns      = 16
	maxBudgetBuckets     = 50_000
)

type budget struct {
	mu      sync.Mutex
	now     func() time.Time
	minute  int64
	global  int
	buckets map[string]int
}

func newBudget(now func() time.Time) *budget {
	return &budget{now: now, buckets: map[string]int{}}
}

// Take reserves one dummy hash for the bucket. False means the budget is spent, for the server or for this bucket.
func (b *budget) Take(bucket string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.now().Unix() / 60
	if m != b.minute {
		b.minute, b.global = m, 0
		clear(b.buckets)
	}
	if b.global >= dummyPerMinute || b.buckets[bucket] >= dummyPerBucketMinute {
		return false
	}
	if len(b.buckets) >= maxBudgetBuckets && b.buckets[bucket] == 0 {
		return false // a table full of this minute's buckets: the unknown one gets no dummy hash
	}
	b.global++
	b.buckets[bucket]++
	return true
}

// sample is the ring of the durations real argon2id runs took inside their slot. One bucket, and one account,
// hold at most 16 entries each: a further duration from them replaces their own oldest entry, so no bucket or
// account can steer the distribution. Calibration entries have no source and are replaced as real ones arrive.
type sample struct {
	mu      sync.Mutex
	entries []entry // oldest first
	seq0    uint64
}

type entry struct {
	d       time.Duration
	bucket  string
	account string
	seq     uint64
}

func (s *sample) Add(d time.Duration, bucket, account string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq0++
	e := entry{d: d, bucket: bucket, account: account, seq: s.seq0}
	// the oldest entry of the same source goes first, once the source holds its share
	for _, by := range []func(entry) bool{
		func(o entry) bool { return bucket != "" && o.bucket == bucket },
		func(o entry) bool { return account != "" && o.account == account },
	} {
		n, oldest := 0, -1
		for i, o := range s.entries {
			if by(o) {
				n++
				if oldest < 0 {
					oldest = i
				}
			}
		}
		if n >= samplePerSource {
			s.entries = append(s.entries[:oldest], s.entries[oldest+1:]...)
			s.entries = append(s.entries, e)
			return
		}
	}
	if len(s.entries) >= sampleSize {
		// calibration entries (no source) are replaced first, else the oldest
		drop := 0
		for i, o := range s.entries {
			if o.bucket == "" && o.account == "" {
				drop = i
				break
			}
		}
		s.entries = append(s.entries[:drop], s.entries[drop+1:]...)
	}
	s.entries = append(s.entries, e)
}

// Ready says the sample holds enough durations for the budget to switch to sleeping.
func (s *sample) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries) >= sampleReady
}

// Draw returns a random entry, which carries the median and the jitter of real runs.
func (s *sample) Draw() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) == 0 {
		return 0
	}
	return s.entries[rand.IntN(len(s.entries))].d
}

// Len is for the tests.
func (s *sample) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// seq is how many durations were ever added: the tests count argon2id runs with it.
func (s *sample) seq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq0
}
