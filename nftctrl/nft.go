package nftctrl

import (
	"fmt"
	"net/netip"

	"git.dolansoft.org/dolansoft/k8s-nft-npc/nfds"
	"git.dolansoft.org/dolansoft/k8s-nft-npc/ranges"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"go4.org/netipx"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
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

func New(eventRecorder record.EventRecorder, podIfaceGroup uint32) (*Controller, error) {
	nftc, err := nftables.New(nftables.AsLasting(), nftables.WithSockOptions(func(conn *netlink.Conn) error {
		if err := conn.SetWriteBuffer(1 << 22); err != nil {
			return err
		}
		if err := conn.SetReadBuffer(1 << 22); err != nil {
			return err
		}
		return nil
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to open nftables netlink connection: %w", err)
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
		return nil, fmt.Errorf("unable to list nftables tables: %w", err)
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

	podTrafficChainIng := c.nftConn.AddChain(&nfds.Chain{
		Table:   c.table,
		Name:    "filter_hook_ing",
		Type:    nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward,
		// Hook traffic after IPVS and other shenanigans
		Priority: nftables.ChainPrioritySELinuxLast,
	})
	c.nftConn.AddRule(&nfds.Rule{
		Table: c.table,
		Chain: podTrafficChainIng,
		Exprs: []expr.Any{
			// Accept packets for established or related connections
			&expr.Ct{Key: expr.CtKeySTATE, Register: newRegOffset + 1},
			&expr.Bitwise{SourceRegister: newRegOffset + 1, DestRegister: newRegOffset + 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: newRegOffset + 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
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
		Chain: podTrafficChainIng,
		Exprs: append(ingPrefilter,
			loadIP(dirEgress, 0),
			lookup(Lookup{DestRegister: 0, IsDestRegSet: true, SourceRegister: newRegOffset + 0, Set: c.vmapIng}),
		),
	})

	podTrafficChainEg := c.nftConn.AddChain(&nfds.Chain{
		Table:   c.table,
		Name:    "filter_hook_eg",
		Type:    nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward,
		// Hook traffic after IPVS and other shenanigans
		Priority: nftables.ChainPrioritySELinuxLast,
	})
	c.nftConn.AddRule(&nfds.Rule{
		Table: c.table,
		Chain: podTrafficChainEg,
		Exprs: []expr.Any{
			// Accept packets for established or related connections
			&expr.Ct{Key: expr.CtKeySTATE, Register: newRegOffset + 1},
			&expr.Bitwise{SourceRegister: newRegOffset + 1, DestRegister: newRegOffset + 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: newRegOffset + 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
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
		Chain: podTrafficChainEg,
		Exprs: append(egPrefilter,
			loadIP(dirIngress, 0),
			lookup(Lookup{DestRegister: 0, IsDestRegSet: true, SourceRegister: newRegOffset + 0, Set: c.vmapEg}),
		),
	})
	return c, nil
}

func (c *Controller) Flush() error {
	return c.nftConn.Flush()
}

func (c *Controller) Close() error {
	return c.nftConn.CloseLasting()
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

// objectID returns an identifier for a Kubernetes object which can be used as
// part of the name of an nftables chain or set.
func objectID(obj *metav1.ObjectMeta) string {
	if len(obj.Namespace)+1+len(obj.Name) > 128 {
		// If the combined length of namespace and name is longer than 128 bytes,
		// use the object UID instead. nftables names are limited to 256 characters,
		// and this limit could otherwise be exceeded.
		return string(obj.UID)
	}
	return fmt.Sprintf("%s_%s", obj.Namespace, obj.Name)
}
