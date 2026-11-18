// Package lru is a small fixed-capacity least-recently-used map. It is not
// safe for concurrent use; callers hold their own lock.
package lru

import "container/list"

// Cache holds at most cap entries and evicts the least recently used one.
type Cache[K comparable, V any] struct {
	cap int
	ll  *list.List
	m   map[K]*list.Element
}

type entry[K comparable, V any] struct {
	k K
	v V
}

// New returns a cache of the given capacity (at least 1).
func New[K comparable, V any](capacity int) *Cache[K, V] {
	return &Cache[K, V]{cap: max(capacity, 1), ll: list.New(), m: map[K]*list.Element{}}
}

// Get returns the value for k and marks it recently used.
func (c *Cache[K, V]) Get(k K) (v V, ok bool) {
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*entry[K, V]).v, true
	}
	return v, false
}

// Put stores v for k, evicting the least recently used entry when full.
func (c *Cache[K, V]) Put(k K, v V) {
	if e, ok := c.m[k]; ok {
		e.Value.(*entry[K, V]).v = v
		c.ll.MoveToFront(e)
		return
	}
	c.m[k] = c.ll.PushFront(&entry[K, V]{k, v})
	for c.ll.Len() > c.cap {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*entry[K, V]).k)
	}
}

// Delete removes k.
func (c *Cache[K, V]) Delete(k K) {
	if e, ok := c.m[k]; ok {
		c.ll.Remove(e)
		delete(c.m, k)
	}
}

// Len is the number of entries.
func (c *Cache[K, V]) Len() int { return c.ll.Len() }
