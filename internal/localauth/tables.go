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

// NameLocked says a lock of scope account is held on a name that is not an account (a made-up name). Existing
// accounts keep theirs in the store.
func (t *tables) NameLocked(name string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.name[t.nameKey(name)]
	return r != nil && r.locked(t.now())
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

// Failure is the outcome of recording a failed attempt.
type Failure struct {
	// AccountLock says the failures of the name reached the throttle's max with scope account: the lock belongs on
	// the account (the store) when it exists, and in the name table when it does not (done here).
	AccountLock bool
	Locked      bool // some lock was set by this failure
}

// Fail records a failed attempt of a typed name from a bucket: the bucket's failures, the pair's and the name's.
// lock is the setting: enabled, duration and scope. exists says the name is an account.
func (t *tables) Fail(bucket, name string, exists bool, max int, window time.Duration, lock lockSetting) Failure {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var f Failure

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
		b.lockUntil, f.Locked = now.Add(lock.Duration), true
	}

	nk := t.nameKey(name)
	// the pair: consecutive failures of this name from this bucket
	pk := pairKey{nk, bucket}
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
		if lock.Enabled && lock.Scope == "ip_account" && p.fails >= max && !p.locked(now) {
			p.lockUntil, f.Locked = now.Add(lock.Duration), true
		}
	}

	// the name over all buckets
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
		if lock.Enabled && lock.Scope == "account" && n.fails >= max && !n.locked(now) {
			f.AccountLock, f.Locked = true, true
			if !exists {
				n.lockUntil = now.Add(lock.Duration)
			}
		}
	}
	return f
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

// Succeed clears the pair of a successful sign-in (consecutive failures end). The bucket and name windows run out
// on their own: a success of one person does not forgive the failures of the network.
func (t *tables) Succeed(bucket, name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pk := pairKey{t.nameKey(name), bucket}
	if _, ok := t.pair[pk]; ok {
		delete(t.pair, pk)
		if t.pairsOf[bucket]--; t.pairsOf[bucket] <= 0 {
			delete(t.pairsOf, bucket)
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

// sizes is for the tests.
func (t *tables) sizes() (buckets, pairs, names int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.buck), len(t.pair), len(t.name)
}

type lockSetting struct {
	Enabled  bool
	Duration time.Duration
	Scope    string
}
