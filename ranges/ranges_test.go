package ranges

import (
	"testing"
)

type trivialRanges struct {
	covered []bool
}

func (t trivialRanges) Add(a Range[int]) {
	for i := a.Start; i <= a.End; i++ {
		t.covered[i] = true
	}
}

func (t trivialRanges) Subtract(a Range[int]) {
	for i := a.Start; i <= a.End; i++ {
		t.covered[i] = false
	}
}

func FuzzRanges(f *testing.F) {
	f.Add([]byte{0x44})
	n := 16
	f.Fuzz(func(t *testing.T, data []byte) {
		dut := New[int]()
		ref := trivialRanges{
			covered: make([]bool, n),
		}
		for i, b := range data {
			start := int(b >> 4)
			end := (int(b&0x0f) + start)
			if end >= n {
				end = n - 1
			}
			r := Range[int]{
				Start: start,
				End:   end,
			}
			if i%2 == 0 {
				t.Logf("Adding [%d, %d]", r.Start, r.End)
				dut.Add(r)
				ref.Add(r)
			} else {
				t.Logf("Subtracting [%d, %d]", r.Start, r.End)
				dut.Subtract(r)
				ref.Subtract(r)
			}
			got := trivialRanges{
				covered: make([]bool, n),
			}
			lastEnd := -2
			for it := dut.Iterator(); it.Valid(); it.Next() {
				if lastEnd+1 >= it.Item().Start {
					t.Errorf("Last end %d, next start %d", lastEnd, it.Item().Start)
				}
				if it.Item().End < it.Item().Start {
					t.Errorf("Item [%d, %d] is invalid", it.Item().Start, it.Item().End)
				}
				lastEnd = it.Item().End
				got.Add(it.Item())
			}
			for i := 0; i < n; i++ {
				if got.covered[i] != ref.covered[i] {
					t.Errorf("At position %d: got %v, wanted %v", i, got.covered[i], ref.covered[i])
				}
			}
			if t.Failed() {
				for it := dut.Iterator(); it.Valid(); it.Next() {
					t.Logf("[%d, %d]", it.Item().Start, it.Item().End)
				}
			}
		}
	})
}
