package nftctrl

import (
	"net/netip"

	"git.dolansoft.org/lorenz/k8s-nft-npc/nfds"
	"git.dolansoft.org/lorenz/k8s-nft-npc/ranges"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"go4.org/netipx"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
)

type Controller struct {
	nftConn *nfds.Conn

	table *nfds.Table

	vmapEg  *nfds.Set
	vmapIng *nfds.Set

	nwps       map[cache.ObjectName]*Policy
	rules      map[*Rule]struct{}
	pods       map[cache.ObjectName]*Pod
	namespaces map[string]*Namespace

	eventRecorder record.EventRecorder
}

const tableName = "k8s-nft-npc"

func New(eventRecorder record.EventRecorder, podIfaceGroup uint32) *Controller {
	nftc, err := nftables.New(nftables.AsLasting())
	if err != nil {
		klog.Fatalf("Failed opening nftables netlink connection: %s", err)
	}
	c := &Controller{
		rules:      make(map[*Rule]struct{}),
		nwps:       make(map[cache.ObjectName]*Policy),
		namespaces: make(map[string]*Namespace),
		pods:       make(map[cache.ObjectName]*Pod),

		nftConn: nfds.WrapConn(nftc),

		eventRecorder: eventRecorder,
	}

	// Add delete operations to any tables already present to make sure we start fresh.
	// Do not flush to atomically activate the new tables.
	tables, err := nftc.ListTables()
	if err != nil {
		klog.Fatalf("Unable to list nftables tables: %v", err)
	}
	var hasV4, hasV6 bool
	for _, t := range tables {
		if t.Name == tableName {
			if t.Family == nftables.TableFamilyIPv4 {
				hasV4 = true
			} else if t.Family == nftables.TableFamilyIPv6 {
				hasV6 = true
			}
		}
	}
	if hasV4 {
		nftc.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "k8s-nft-npc"})
	}
	if hasV6 {
		nftc.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: "k8s-nft-npc"})
	}

	c.table = &nfds.Table{
		Name: "k8s-nft-npc",
	}
	c.nftConn.AddTable(c.table)

	podTrafficChain := c.nftConn.AddChain(&nfds.Chain{
		Table:   c.table,
		Name:    "filter_hook",
		Type:    nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward,
		// Hook traffic after IPVS and other shenanigans
		Priority: nftables.ChainPrioritySELinuxLast,
	})
	c.vmapIng = &nfds.Set{
		Table:        c.table,
		Name:         "vmap_ing",
		IsMap:        true,
		KeyByteOrder: binaryutil.BigEndian,
		KeyType:      nftables.TypeIPAddr,
		KeyType6:     nftables.TypeIP6Addr,
		DataType:     nftables.TypeVerdict,
	}
	c.nftConn.AddSet(c.vmapIng, []nftables.SetElement{})
	var ingPrefilter []expr.Any
	if podIfaceGroup != 0 {
		ingPrefilter = append(ingPrefilter, &expr.Meta{Key: expr.MetaKeyOIFGROUP, Register: newRegOffset + 0},
			&expr.Cmp{Op: expr.CmpOpEq, Register: newRegOffset + 0, Data: binaryutil.NativeEndian.PutUint32(podIfaceGroup)})
	}
	c.nftConn.AddRule(&nfds.Rule{
		Table: c.table,
		Chain: podTrafficChain,
		Exprs: append(ingPrefilter,
			loadIP(dirEgress, 0),
			lookup(Lookup{DestRegister: 0, IsDestRegSet: true, SourceRegister: newRegOffset + 0, Set: c.vmapIng}),
		),
	})

	c.vmapEg = &nfds.Set{
		Table:        c.table,
		Name:         "vmap_eg",
		IsMap:        true,
		KeyByteOrder: binaryutil.BigEndian,
		KeyType:      nftables.TypeIPAddr,
		KeyType6:     nftables.TypeIP6Addr,
		DataType:     nftables.TypeVerdict,
	}
	c.nftConn.AddSet(c.vmapEg, []nftables.SetElement{})
	var egPrefilter []expr.Any
	if podIfaceGroup != 0 {
		egPrefilter = append(egPrefilter, &expr.Meta{Key: expr.MetaKeyIIFGROUP, Register: newRegOffset + 0},
			&expr.Cmp{Op: expr.CmpOpEq, Register: newRegOffset + 0, Data: binaryutil.NativeEndian.PutUint32(podIfaceGroup)})
	}
	c.nftConn.AddRule(&nfds.Rule{
		Table: c.table,
		Chain: podTrafficChain,
		Exprs: append(egPrefilter,
			loadIP(dirIngress, 0),
			lookup(Lookup{DestRegister: 0, IsDestRegSet: true, SourceRegister: newRegOffset + 0, Set: c.vmapEg}),
		),
	})
	return c
}

func (c *Controller) Flush() error {
	return c.nftConn.Flush()
}

func prefixToRange(net netip.Prefix) ranges.Range[netip.Addr] {
	return ranges.Range[netip.Addr]{
		Start: net.Masked().Addr(),
		End:   netipx.PrefixLastIP(net),
	}
}

func rangeToInterval(p ranges.Range[netip.Addr]) []nftables.SetElement {
	endKey := p.End.AsSlice()
	// Increment IP by one to get exclusive upper bound
	for i := len(endKey) - 1; i >= 0; i-- {
		endKey[i]++
		if endKey[i] != 0 {
			break
		}
	}
	return []nftables.SetElement{{
		Key: p.Start.AsSlice(),
	}, {
		Key:         endKey,
		IntervalEnd: true,
	}}
}

func lessAddrs(a, b netip.Addr) bool {
	return a.Less(b)
}

func closest(a netip.Addr, before bool) netip.Addr {
	slice := a.AsSlice()
	for i := len(slice) - 1; i >= 0; i-- {
		if before {
			slice[i]--
			if slice[i] != 255 {
				break
			}
		} else {
			slice[i]++
			if slice[i] != 0 {
				break
			}
		}
	}
	out, ok := netip.AddrFromSlice(slice)
	if !ok {
		panic("bad closest ip")
	}
	return out
}
