package localauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sort"
	"sync"
	"time"
)

// The in-memory counters of the sign-in protection (docs/design-local-accounts.md, 8.6): failures per bucket (the
// throttle), per (name, bucket) pair and per name, with the locks of scope ip, ip_account and, for names that do not
// exist, account. Names are never kept: the tables are keyed by an HMAC under a key made at start. They are
// bounded; when full, the rows with the fewest failures go first, unlocked before locked, and a name or pair that
// cannot get a row gets the throttle only, never a lock.

// Table bounds (constants, 8.6).
const (
	maxPairRows           = 100_000
	maxPairRowsPerBucket  = 1_000
	maxNameRows           = 50_000
	maxNewNameRowsPerHour = 200
	maxBucketRows         = 100_000
	floodPerMinute        = 600
)

// row is a failure count in a window, and a lock.
type row struct {
	fails     int
	start     time.Time // when the window of fails began
	lockUntil time.Time
	last      time.Time
}

func (r *row) live(now time.Time, window time.Duration) {
	if now.Sub(r.start) >= window || r.start.IsZero() {
		r.fails, r.start = 0, now
	}
}

func (r *row) locked(now time.Time) bool { return r.lockUntil.After(now) }

type pairKey struct {
	name   [16]byte
	bucket string
}

type newRows struct {
	n    int
	hour int64
}

type tables struct {
	mu   sync.Mutex
	key  []byte // HMAC key of this start
	now  func() time.Time
	buck map[string]*row
	pair map[pairKey]*row
	name map[[16]byte]*row
	// pairsOf counts the pair rows of one bucket; newNames counts the name rows a bucket made this hour
	pairsOf  map[string]int
	newNames map[string]*newRows
	flood    map[string]*minuteCount
}

type minuteCount struct {
	minute int64
	n      int
}

func newTables(now func() time.Time) *tables {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("localauth: " + err.Error())
	}
	return &tables{key: k, now: now, buck: map[string]*row{}, pair: map[pairKey]*row{}, name: map[[16]byte]*row{},
		pairsOf: map[string]int{}, newNames: map[string]*newRows{}, flood: map[string]*minuteCount{}}
}

func (t *tables) nameKey(name string) [16]byte {
	m := hmac.New(sha256.New, t.key)
	m.Write([]byte(name))
	var k [16]byte
	copy(k[:], m.Sum(nil))
	return k
}

// Flood counts a request of the bucket in the current minute and says whether it is above the ceiling.
func (t *tables) Flood(bucket string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	min := t.now().Unix() / 60
	c := t.flood[bucket]
	if c == nil {
		if len(t.flood) >= maxBucketRows {
			for k, v := range t.flood { // an old minute goes first
				if v.minute != min {
					delete(t.flood, k)
				}
			}
			if len(t.flood) >= maxBucketRows {
				return true // a table full of this minute's buckets: refuse the unknown one
			}
		}
		c = &minuteCount{minute: min}
		t.flood[bucket] = c
	}
	if c.minute != min {
		c.minute, c.n = min, 0
	}
	c.n++
	return c.n > floodPerMinute
}

// Check is what the tables say about an attempt before the name is looked up: whether the bucket is over the
// throttle and whether a lock of scope ip or ip_account holds.
type Check struct {
	Throttled bool
	Locked    bool // scope ip, or ip_account for this pair
}

// Pre reads the throttle and the locks of scope ip and ip_account. ip_account is read for every typed name.
func (t *tables) Pre(bucket, name string, max int, window time.Duration) Check {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var c Check
	if r := t.buck[bucket]; r != nil {
		r.live(now, window)
		c.Throttled = r.fails >= max
		c.Locked = r.locked(now)
	}
	if r := t.pair[pairKey{t.nameKey(name), bucket}]; r != nil {
		c.Locked = c.Locked || r.locked(now)
	}
	return c
}

// NameFails is the failures of the typed name over all buckets in the window.
func (t *tables) NameFails(name string, window time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.name[t.nameKey(name)]
	if r == nil {
		return 0
	}
	r.live(t.now(), window)
	return r.fails
}

// ticket is the reservation of one attempt in the tables: Begin counts the attempt as a failure before any work is done, so that
// a burst of parallel requests cannot all be checked against the counts that were there before the first of them. A success gives
// it back (Refund); a failure keeps it. The locks the attempt set are remembered so that a success undoes them too.
type ticket struct {
	counted                          bool
	bucket                           string
	pk                               pairKey
	nk                               [16]byte
	pair, name                       bool
	lockedIP, lockedPair, lockedName bool
}

// AccountLock says this attempt's failure reached the throttle's max for the name with scope account: the lock belongs in the
// store too when the name is an account.
func (k ticket) AccountLock() bool { return k.lockedName }

// Begin checks the throttle and the locks and, when the attempt may go on (or enforce is false: a verified passkey goes past
// both), counts it against the bucket, the pair and the name in the same critical section, setting a lock when the count
// reaches max. The check that refuses an attempt is read from the same rows that the count is written to.
func (t *tables) Begin(bucket, name string, max int, window time.Duration, lock lockSetting, enforce bool) (ticket, Check) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	nk := t.nameKey(name)
	pk := pairKey{nk, bucket}
	var c Check
	if r := t.buck[bucket]; r != nil {
		r.live(now, window)
		c.Throttled = r.fails >= max
		c.Locked = r.locked(now)
	}
	if r := t.pair[pk]; r != nil {
		c.Locked = c.Locked || r.locked(now)
	}
	if r := t.name[nk]; r != nil {
		c.Locked = c.Locked || r.locked(now)
	}
	if enforce && (c.Throttled || c.Locked) {
		return ticket{}, c
	}
	tk := ticket{counted: true, bucket: bucket, pk: pk, nk: nk}

	b := t.buck[bucket]
	if b == nil {
		if len(t.buck) >= maxBucketRows {
			evict(t.buck, now, window, func(r *row) bool { return r.locked(now) })
		}
		b = &row{}
		if len(t.buck) < maxBucketRows {
			t.buck[bucket] = b
		}
	}
	b.live(now, window)
	b.fails++
	b.last = now
	if lock.Enabled && lock.Scope == "ip" && b.fails >= max && !b.locked(now) {
		b.lockUntil, tk.lockedIP = now.Add(lock.Duration), true
	}

	p := t.pair[pk]
	if p == nil && t.pairsOf[bucket] < maxPairRowsPerBucket {
		if len(t.pair) >= maxPairRows {
			t.evictPairs(now, window)
		}
		if len(t.pair) < maxPairRows {
			p = &row{}
			t.pair[pk] = p
			t.pairsOf[bucket]++
		}
	}
	if p != nil {
		p.live(now, window)
		p.fails++
		p.last = now
		tk.pair = true
		if lock.Enabled && lock.Scope == "ip_account" && p.fails >= max && !p.locked(now) {
			p.lockUntil, tk.lockedPair = now.Add(lock.Duration), true
		}
	}

	n := t.name[nk]
	if n == nil && t.mayAddName(bucket, now) {
		if len(t.name) >= maxNameRows {
			evictNames(t.name, now, window)
		}
		if len(t.name) < maxNameRows {
			n = &row{}
			t.name[nk] = n
		}
	}
	if n != nil {
		n.live(now, window)
		n.fails++
		n.last = now
		tk.name = true
		if lock.Enabled && lock.Scope == "account" && n.fails >= max && !n.locked(now) {
			n.lockUntil, tk.lockedName = now.Add(lock.Duration), true
		}
	}
	return tk, c
}

// Refund gives back what Begin counted, for an attempt that turned out to be a success (or one that never reached the
// password check: busy). The pair of a success is gone altogether (consecutive failures end), and a lock this attempt set is
// lifted.
func (t *tables) Refund(tk ticket) {
	if !tk.counted {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if r := t.buck[tk.bucket]; r != nil {
		if r.fails > 0 {
			r.fails--
		}
		if tk.lockedIP {
			r.lockUntil = time.Time{}
		}
	}
	if _, ok := t.pair[tk.pk]; ok {
		delete(t.pair, tk.pk)
		if t.pairsOf[tk.bucket]--; t.pairsOf[tk.bucket] <= 0 {
			delete(t.pairsOf, tk.bucket)
		}
	}
	if r := t.name[tk.nk]; r != nil {
		if r.fails > 0 {
			r.fails--
		}
		if tk.lockedName {
			r.lockUntil = time.Time{}
		}
	}
}

// Fail counts a failure that had no reservation (a link that is not valid): the same counting, no check.
func (t *tables) Fail(bucket, name string, max int, window time.Duration, lock lockSetting) {
	t.Begin(bucket, name, max, window, lock, false)
}

// mayAddName limits the name rows one bucket makes to maxNewNameRowsPerHour an hour.
func (t *tables) mayAddName(bucket string, now time.Time) bool {
	h := now.Unix() / 3600
	r := t.newNames[bucket]
	if r == nil {
		if len(t.newNames) >= maxBucketRows {
			for k, v := range t.newNames {
				if v.hour != h {
					delete(t.newNames, k)
				}
			}
			if len(t.newNames) >= maxBucketRows {
				return false
			}
		}
		r = &newRows{hour: h}
		t.newNames[bucket] = r
	}
	if r.hour != h {
		r.hour, r.n = h, 0
	}
	if r.n >= maxNewNameRowsPerHour {
		return false
	}
	r.n++
	return true
}

// evict removes the idle rows first, then the rows with the fewest failures, unlocked before locked, locked ones too if
// that is what it takes (so made-up names locked for days cannot fill the table).
func evict[K comparable](m map[K]*row, now time.Time, window time.Duration, isLocked func(*row) bool) {
	target := len(m) * 9 / 10
	for k, r := range m {
		if now.Sub(r.start) >= window && !isLocked(r) {
			delete(m, k)
		}
	}
	if len(m) <= target {
		return
	}
	type kv struct {
		k K
		r *row
	}
	var rows []kv
	for k, r := range m {
		rows = append(rows, kv{k, r})
	}
	sort.Slice(rows, func(i, j int) bool {
		li, lj := isLocked(rows[i].r), isLocked(rows[j].r)
		if li != lj {
			return !li
		}
		return rows[i].r.fails < rows[j].r.fails
	})
	for _, e := range rows {
		if len(m) <= target {
			break
		}
		delete(m, e.k)
	}
}

func evictNames(m map[[16]byte]*row, now time.Time, window time.Duration) {
	evict(m, now, window, func(r *row) bool { return r.locked(now) })
}

func (t *tables) evictPairs(now time.Time, window time.Duration) {
	before := map[string]int{}
	for k := range t.pair {
		before[k.bucket]++
	}
	evict(t.pair, now, window, func(r *row) bool { return r.locked(now) })
	left := map[string]int{}
	for k := range t.pair {
		left[k.bucket]++
	}
	for b, n := range before {
		if left[b] == 0 {
			delete(t.pairsOf, b)
		} else if left[b] != n {
			t.pairsOf[b] = left[b]
		}
	}
}

// ClearName forgets a name's rows (an unlock by an administrator reaches the memory tables too).
func (t *tables) ClearName(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	nk := t.nameKey(name)
	delete(t.name, nk)
	for pk := range t.pair {
		if pk.name == nk {
			delete(t.pair, pk)
			if t.pairsOf[pk.bucket]--; t.pairsOf[pk.bucket] <= 0 {
				delete(t.pairsOf, pk.bucket)
			}
		}
	}
}

type lockSetting struct {
	Enabled  bool
	Duration time.Duration
	Scope    string
}
