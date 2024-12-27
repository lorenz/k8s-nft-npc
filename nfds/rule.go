package nfds

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type Rule struct {
	Table    *Table
	Chain    *Chain
	Position *Rule
	// The list of possible flags are specified by nftnl_rule_attr, see
	// https://git.netfilter.org/libnftnl/tree/include/libnftnl/rule.h#n21
	// Current nftables go implementation supports only
	// NFTNL_RULE_POSITION flag for setting rule at position 0
	Flags    uint32
	Exprs    []expr.Any
	UserData []byte

	v4 *nftables.Rule
	v6 *nftables.Rule
}

func (cc *Conn) AddRule(r *Rule) *Rule {
	r.v4 = &nftables.Rule{
		Table:    r.Table.v4,
		Chain:    r.Chain.v4,
		Flags:    r.Flags,
		Exprs:    r.Exprs,
		UserData: r.UserData,
	}
	if r.Position != nil {
		r.v4.Position = r.Position.v4.Handle
	}
	cc.c.AddRule(r.v4)
	r.v6 = &nftables.Rule{
		Table:    r.Table.v6,
		Chain:    r.Chain.v6,
		Flags:    r.Flags,
		Exprs:    r.Exprs,
		UserData: r.UserData,
	}
	if r.Position != nil {
		r.v6.Position = r.Position.v6.Handle
	}
	cc.c.AddRule(r.v6)
	return r
}

func (cc *Conn) InsertRule(r *Rule) *Rule {
	r.v4 = &nftables.Rule{
		Table:    r.Table.v4,
		Chain:    r.Chain.v4,
		Flags:    r.Flags,
		Exprs:    r.Exprs,
		UserData: r.UserData,
	}
	if r.Position != nil {
		r.v4.Position = r.Position.v4.Handle
	}
	cc.c.InsertRule(r.v4)
	r.v6 = &nftables.Rule{
		Table:    r.Table.v6,
		Chain:    r.Chain.v6,
		Flags:    r.Flags,
		Exprs:    r.Exprs,
		UserData: r.UserData,
	}
	if r.Position != nil {
		r.v6.Position = r.Position.v6.Handle
	}
	cc.c.InsertRule(r.v6)
	return r
}

func (cc *Conn) DelRule(r *Rule) error {
	cc.c.DelRule(r.v4)
	cc.c.DelRule(r.v6)
	return nil
}
