package nfds

import "github.com/google/nftables"

type Chain struct {
	Name     string
	Table    *Table
	Hooknum  *nftables.ChainHook
	Priority *nftables.ChainPriority
	Type     nftables.ChainType
	Policy   *nftables.ChainPolicy
	Device   string

	v4 *nftables.Chain
	v6 *nftables.Chain
}

func (cc *Conn) AddChain(c *Chain) *Chain {
	c.v4 = cc.c.AddChain(&nftables.Chain{
		Name:     c.Name,
		Table:    c.Table.v4,
		Hooknum:  c.Hooknum,
		Priority: c.Priority,
		Type:     c.Type,
		Policy:   c.Policy,
		Device:   c.Device,
	})
	c.v6 = cc.c.AddChain(&nftables.Chain{
		Name:     c.Name,
		Table:    c.Table.v6,
		Hooknum:  c.Hooknum,
		Priority: c.Priority,
		Type:     c.Type,
		Policy:   c.Policy,
		Device:   c.Device,
	})
	return c
}

func (cc *Conn) DelChain(c *Chain) {
	cc.c.DelChain(c.v4)
	cc.c.DelChain(c.v6)
}
