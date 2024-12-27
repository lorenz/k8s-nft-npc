package ranges

import (
	"fmt"

	"github.com/igrmk/treemap/v2"
	"golang.org/x/exp/constraints"
)

type Range[T any] struct {
	Start T
	End   T
}

type Ranges[T any] struct {
	t       *treemap.TreeMap[T, T]
	less    func(a, b T) bool
	closest func(a T, before bool) T
}

func (r Ranges[T]) assertValid(a Range[T]) {
	if r.less(a.End, a.Start) {
		panic(fmt.Sprintf("bad range: start %v, end %v", a.Start, a.End))
	}
}

func defaultCompare[T constraints.Integer](a, b T) bool {
	return a < b
}

func defaultClosest[T constraints.Integer](a T, before bool) T {
	if before {
		return a - 1
	} else {
		return a + 1
	}
}

func New[T constraints.Integer]() *Ranges[T] {
	return &Ranges[T]{
		t:       treemap.New[T, T](),
		less:    defaultCompare[T],
		closest: defaultClosest[T],
	}
}

func NewWithCompare[T any](cmp func(a, b T) bool, closest func(a T, before bool) T) *Ranges[T] {
	return &Ranges[T]{
		t:       treemap.NewWithKeyCompare[T, T](cmp),
		less:    cmp,
		closest: closest,
	}
}

func (r *Ranges[T]) Subtract(a Range[T]) {
	r.assertValid(a)
	if r.t.Len() == 0 {
		return
	}
	var keysToRemove []T
	it := r.t.LowerBound(a.Start)
	// Check if we have a previous element and it overlaps
	if !it.Valid() || r.less(r.t.Iterator().Key(), it.Key()) {
		it.Prev()

		if !r.less(it.Value(), a.Start) {
			currentEnd := it.Value()
			r.t.Set(it.Key(), r.closest(a.Start, true))

			if r.less(a.End, currentEnd) {
				r.t.Set(r.closest(a.End, false), currentEnd)
				return
			}
		}

		it.Next()
	}
	for ; it.Valid(); it.Next() {
		if r.less(a.End, it.Key()) {
			// End of new range doesn't touch next start, we're done
			break
		}
		if r.less(a.End, it.Value()) {
			// Shrink existing range down
			r.t.Set(r.closest(a.End, false), it.Value())
		}
		// Remove old range
		keysToRemove = append(keysToRemove, it.Key())
	}
	for _, k := range keysToRemove {
		r.t.Del(k)
	}
}

func (r *Ranges[T]) Add(a Range[T]) {
	r.assertValid(a)
	if r.t.Len() == 0 {
		r.t.Set(a.Start, a.End)
		return
	}
	var keysToRemove []T
	it := r.t.LowerBound(a.Start)
	// Check if we have a previous element
	if !it.Valid() || r.less(r.t.Iterator().Key(), it.Key()) {
		it.Prev()

		if !r.less(it.Value(), a.End) {
			// Already fully covered, new range adds nothing
			return
		}

		if !r.less(it.Value(), a.Start) { // TODO: exact adjacency not getting joined
			// Extend new range to replace adjacent/overlapping existing range
			a.Start = it.Key()
			keysToRemove = append(keysToRemove, it.Key())
		}
		it.Next()
	}
	for ; it.Valid(); it.Next() {
		if r.less(a.End, it.Key()) { // TODO: exact adjacency not getting joined
			// End of new range doesn't touch next start, we're done
			break
		}
		if r.less(a.End, it.Value()) {
			// Extend end of new range to replace adjacent/overlapping existing range
			a.End = it.Value()
		}
		// Delete old range (partially) covered by new one
		keysToRemove = append(keysToRemove, it.Key())
	}
	for _, k := range keysToRemove {
		r.t.Del(k)
	}
	r.t.Set(a.Start, a.End)
}

func (r *Ranges[T]) Len() int {
	return r.t.Len()
}

type Iterator[T any] struct {
	i treemap.ForwardIterator[T, T]
}

func (i *Iterator[T]) Valid() bool {
	return i.i.Valid()
}

func (i *Iterator[T]) Next() {
	i.i.Next()
}

func (i *Iterator[T]) Item() Range[T] {
	return Range[T]{Start: i.i.Key(), End: i.i.Value()}
}

func (r Ranges[T]) Iterator() Iterator[T] {
	return Iterator[T]{i: r.t.Iterator()}
}
