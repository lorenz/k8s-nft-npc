package nfds

import (
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"golang.org/x/sys/unix"
)

type Set struct {
	Table      *Table
	Name       string
	Anonymous  bool
	Constant   bool
	Interval   bool
	IsMap      bool
	HasTimeout bool
	Counter    bool
	// Can be updated per evaluation path, per `nft list ruleset`
	// indicates that set contains "flags dynamic"
	// https://git.netfilter.org/libnftnl/tree/include/linux/netfilter/nf_tables.h?id=84d12cfacf8ddd857a09435f3d982ab6250d250c#n298
	Dynamic bool
	// Indicates that the set contains a concatenation
	// https://git.netfilter.org/nftables/tree/include/linux/netfilter/nf_tables.h?id=d1289bff58e1878c3162f574c603da993e29b113#n306
	Concatenation bool
	Timeout       time.Duration
	KeyType       nftables.SetDatatype
	KeyType6      nftables.SetDatatype
	DataType      nftables.SetDatatype
	DataType6     nftables.SetDatatype
	// Either host (binaryutil.NativeEndian) or big (binaryutil.BigEndian) endian as per
	// https://git.netfilter.org/nftables/tree/include/datatype.h?id=d486c9e626405e829221b82d7355558005b26d8a#n109
	KeyByteOrder binaryutil.ByteOrder

	v4 *nftables.Set
	v6 *nftables.Set
}

func (s *Set) Reference(fam uint8) (uint32, string) {
	if fam == unix.NFPROTO_IPV4 {
		return s.v4.ID, s.v4.Name
	} else {
		return s.v6.ID, s.v6.Name
	}
}

func (cc *Conn) AddSet(s *Set, elems []nftables.SetElement) error {
	s.v4 = &nftables.Set{
		Table:         s.Table.v4,
		Name:          s.Name,
		Anonymous:     s.Anonymous,
		Constant:      s.Constant,
		Interval:      s.Interval,
		IsMap:         s.IsMap,
		HasTimeout:    s.HasTimeout,
		Counter:       s.Counter,
		Dynamic:       s.Dynamic,
		Concatenation: s.Concatenation,
		Timeout:       s.Timeout,
		KeyType:       s.KeyType,
		DataType:      s.DataType,
		KeyByteOrder:  s.KeyByteOrder,
	}
	s.v6 = &nftables.Set{
		Table:         s.Table.v6,
		Name:          s.Name,
		Anonymous:     s.Anonymous,
		Constant:      s.Constant,
		Interval:      s.Interval,
		IsMap:         s.IsMap,
		HasTimeout:    s.HasTimeout,
		Counter:       s.Counter,
		Dynamic:       s.Dynamic,
		Concatenation: s.Concatenation,
		Timeout:       s.Timeout,
		KeyByteOrder:  s.KeyByteOrder,
	}
	if s.KeyType6.GetNFTMagic() == 0 {
		s.v6.KeyType = s.KeyType
	} else {
		s.v6.KeyType = s.KeyType6
	}
	if s.DataType6.GetNFTMagic() == 0 {
		s.v6.DataType = s.DataType
	} else {
		s.v6.DataType = s.DataType6
	}
	vals4, vals6, err := cc.splitVals(s, elems)
	if err != nil {
		return err
	}
	if err := cc.c.AddSet(s.v4, vals4); err != nil {
		return err
	}
	return cc.c.AddSet(s.v6, vals6)

}

func (cc *Conn) DelSet(s *Set) {
	cc.c.DelSet(s.v4)
	cc.c.DelSet(s.v6)
}

func (cc *Conn) splitVals(s *Set, vals []nftables.SetElement) (vals4, vals6 []nftables.SetElement, err error) {
	switch {
	case s.KeyType6.Bytes != s.KeyType.Bytes:
		for _, val := range vals {
			switch len(val.Key) {
			case int(s.KeyType6.Bytes):
				vals6 = append(vals6, val)
			case int(s.KeyType.Bytes):
				vals4 = append(vals4, val)
			default:
				panic("bad length, fix me later")
			}
		}
	case s.DataType.Bytes != s.DataType6.Bytes:
		for _, val := range vals {
			switch len(val.Val) {
			case int(s.DataType6.Bytes):
				vals6 = append(vals6, val)
			case int(s.DataType.Bytes):
				vals4 = append(vals4, val)
			default:
				panic("bad length, fix me later")
			}
		}
	default:
		return vals, vals, nil
	}
	return vals4, vals6, nil
}

func (cc *Conn) SetAddElements(s *Set, vals []nftables.SetElement) error {
	vals4, vals6, err := cc.splitVals(s, vals)
	if err != nil {
		return err
	}
	if err := cc.c.SetAddElements(s.v4, vals4); err != nil {
		return err
	}
	return cc.c.SetAddElements(s.v6, vals6)

}

func (cc *Conn) SetDeleteElements(s *Set, vals []nftables.SetElement) error {
	vals4, vals6, err := cc.splitVals(s, vals)
	if err != nil {
		return err
	}
	if err := cc.c.SetDeleteElements(s.v4, vals4); err != nil {
		return err
	}
	return cc.c.SetDeleteElements(s.v6, vals6)
}
