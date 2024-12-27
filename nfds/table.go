package nfds

import "github.com/google/nftables"

type Table struct {
	Name  string
	Use   uint32
	Flags uint32

	v4 *nftables.Table
	v6 *nftables.Table
}

func (cc *Conn) AddTable(t *Table) *Table {
	t.v4 = cc.c.AddTable(&nftables.Table{
		Name:   t.Name,
		Use:    t.Use,
		Flags:  t.Flags,
		Family: nftables.TableFamilyIPv4,
	})
	t.v6 = cc.c.AddTable(&nftables.Table{
		Name:   t.Name,
		Use:    t.Use,
		Flags:  t.Flags,
		Family: nftables.TableFamilyIPv6,
	})
	return t
}

func (cc *Conn) FlushTable(t *Table) {
	cc.c.FlushTable(t.v4)
	cc.c.FlushTable(t.v6)
}
