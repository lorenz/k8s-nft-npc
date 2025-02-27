package nftctrl

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"git.dolansoft.org/dolansoft/k8s-nft-npc/nfds"
	"git.dolansoft.org/dolansoft/k8s-nft-npc/ranges"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	nwkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"
)

type Policy struct {
	Namespace       string
	ID              string
	PodSelector     labels.Selector
	IngressRuleMeta []*Rule
	EgressRuleMeta  []*Rule

	ingressChain *nfds.Chain
	egressChain  *nfds.Chain
	podRefs      map[*Pod]struct{}
}

type Rule struct {
	Namespace     string
	PodSelectors  []PodSelector
	PodIPSet      *nfds.Set
	NamedPortMeta []RuleNamedPortMeta
	NamedPortSet  *nfds.Set

	podRefs map[*Pod]struct{}
}

type RuleNamedPortMeta struct {
	PortName string
	Protocol uint8
}

type RuleNumberedPortMeta struct {
	Protocol uint8
	Port     uint16
	EndPort  uint16
}

func (nm RuleNumberedPortMeta) NeedsInterval() bool {
	return nm.Port != nm.EndPort && !(nm.Port == 0 && nm.EndPort == math.MaxUint16)
}

type PodSelector struct {
	NamespaceSelector labels.Selector
	PodSelector       labels.Selector
}

func (sel PodSelector) Matches(p *Pod, selNs string, namespaces map[string]*Namespace) bool {
	if sel.NamespaceSelector == labels.Nothing() {
		if selNs != p.Namespace {
			return false
		}
	} else {
		ns, ok := namespaces[p.Namespace]
		if !ok || !sel.NamespaceSelector.Matches(ns.Labels) {
			return false
		}
	}
	if !sel.PodSelector.Matches(p.Labels) {
		return false
	}
	return true
}

func (c *Controller) createPeers(ch *nfds.Chain, peers []nwkv1.NetworkPolicyPeer, ports []nwkv1.NetworkPolicyPort, prefix string, dir direction, nwp *nwkv1.NetworkPolicy) *Rule {
	var meta Rule

	meta.podRefs = make(map[*Pod]struct{})
	meta.Namespace = nwp.Namespace

	ipRangesPermitted := ranges.NewWithCompare(lessAddrs, closest)

	for _, src := range peers {
		if src.IPBlock != nil {
			if src.NamespaceSelector != nil {
				c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPeer", "ipBlock cannot be combined with namespaceSelector, ignoring")
				continue
			}
			if src.PodSelector != nil {
				c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPeer", "ipBlock cannot be combined with podSelector, ignoring")
				continue
			}
			p, err := netip.ParsePrefix(src.IPBlock.CIDR)
			if err != nil {
				c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPeer", "ipBlock CIDR invalid: %v", err)
				continue
			}
			thisBlock := ranges.NewWithCompare(lessAddrs, closest)
			thisBlock.Add(prefixToRange(p))
			for _, excl := range src.IPBlock.Except {
				pExcl, err := netip.ParsePrefix(excl)
				if err != nil {
					c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPeer", "ipBlock except value %q invalid: %v", excl, err)
					continue
				}
				if !p.Contains(pExcl.Masked().Addr()) || !p.Contains(netipx.PrefixLastIP(pExcl)) {
					c.eventRecorder.Eventf(nwp, corev1.EventTypeNormal, "SuspiciousIPBlock", "ipBlock except value %q is not contained in parent", excl, err)
				}
				thisBlock.Subtract(prefixToRange(pExcl))
			}
			for it := thisBlock.Iterator(); it.Valid(); it.Next() {
				ipRangesPermitted.Add(it.Item())
			}
		}
		nsSel, err := metav1.LabelSelectorAsSelector(src.NamespaceSelector)
		if err != nil {
			c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPeer", "namespaceSelector invalid: %v", err)
			continue
		}
		podSel, err := metav1.LabelSelectorAsSelector(src.PodSelector)
		if err != nil {
			c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPeer", "podSelector invalid: %v", err)
			continue
		}
		// Skip adding selectors which match nothing
		if nsSel != labels.Nothing() || podSel != labels.Nothing() {
			if podSel == labels.Nothing() {
				// If a namespace selector is present, match all pods of
				// that namespace if no pod selector is present.
				podSel = labels.Everything()
			}
			meta.PodSelectors = append(meta.PodSelectors, PodSelector{
				NamespaceSelector: nsSel,
				PodSelector:       podSel,
			})
		}
	}

	var dynPorts []RuleNamedPortMeta
	var portProtos []RuleNumberedPortMeta
	for _, port := range ports {
		// TCP is default
		var proto uint8 = unix.IPPROTO_TCP
		if port.Protocol != nil {
			var ok bool
			proto, ok = parseProtocol(*port.Protocol)
			if !ok {
				c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "UnknownProtocol", "port protocol %q unknown, ignoring port", *port.Protocol)
				continue
			}
		}
		if port.Port == nil {
			portProtos = append(portProtos, RuleNumberedPortMeta{
				Protocol: proto,
				Port:     0,
				EndPort:  math.MaxUint16,
			})

		} else if port.Port.Type == intstr.String {
			dynPorts = append(dynPorts, RuleNamedPortMeta{
				PortName: port.Port.StrVal,
				Protocol: proto,
			})
		} else if port.Port.Type == intstr.Int {
			if port.Port.IntVal > math.MaxUint16 {
				c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPort", "port number %d is out of range, ignoring port", port.Port.IntVal)
				continue
			}

			var startPort uint16 = uint16(port.Port.IntVal)
			var endPort uint16 = startPort
			if port.EndPort != nil {
				if *port.EndPort < port.Port.IntVal {
					c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPort", "end port %d is lower than start port %d, ignoring port range", *port.EndPort, port.Port.IntVal)
					continue
				}
				if *port.EndPort > math.MaxUint16 {
					c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPort", "end port number %d is out of range, ignoring port", *port.EndPort)
					continue
				}
				endPort = uint16(*port.EndPort)
			}
			portProtos = append(portProtos, RuleNumberedPortMeta{
				Protocol: proto,
				Port:     startPort,
				EndPort:  endPort,
			})
		}
	}

	// Handle special named ports first as they work differently from the
	// rest of the system.
	if len(dynPorts) > 0 && (len(meta.PodSelectors) > 0 || len(peers) == 0) {
		namedPortSet := nfds.Set{
			Table:         c.table,
			Name:          prefix + "_namedports",
			KeyType:       nftables.MustConcatSetType(nftables.TypeInetProto, nftables.TypeInetService, nftables.TypeIPAddr),
			KeyType6:      nftables.MustConcatSetType(nftables.TypeInetProto, nftables.TypeInetService, nftables.TypeIP6Addr),
			KeyByteOrder:  binaryutil.BigEndian,
			Concatenation: true,
		}
		c.nftConn.AddSet(&namedPortSet, []nftables.SetElement{})
		meta.NamedPortSet = &namedPortSet
		meta.NamedPortMeta = dynPorts
		c.nftConn.AddRule(&nfds.Rule{
			Table: c.table,
			Chain: ch,
			Exprs: []expr.Any{
				// Load Layer 4 protocol into register 0
				&expr.Meta{
					Key:      expr.MetaKeyL4PROTO,
					Register: newRegOffset + 0,
				},
				// Load Port into register 1
				loadDstPort(1),
				// Load IP address into register 2 (IPv4) or 2-5 (IPv6)
				loadIP(dir, 2),
				// Abort if IP/port/L4 protocol is not in permitted set
				lookup(Lookup{
					Set:            &namedPortSet,
					SourceRegister: newRegOffset + 0,
				}),
				// Accept packet
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		})
	}

	if len(portProtos) == 0 && len(ports) > 0 {
		// If non-numbered port rules exist but no numbered ones, skip numbered
		// traffic, which is handled by the rest of this function.
		return &meta
	}

	var portProtoExprs []expr.Any
	if len(portProtos) > 0 {
		// Shortcut for simple port restrictions
		if len(portProtos) == 1 && !portProtos[0].NeedsInterval() {
			p := portProtos[0]
			// Load L4 protocol into register 0
			portProtoExprs = append(portProtoExprs, &expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: newRegOffset + 0,
			}, &expr.Cmp{ // Compare register 0 with expected protocol
				Op:       expr.CmpOpEq,
				Register: newRegOffset + 0,
				Data:     []byte{p.Protocol},
			})
			if p.Port != 0 || p.EndPort != math.MaxUint16 {
				portProtoExprs = append(portProtoExprs, loadDstPort(1), &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: newRegOffset + 1,
					Data:     binary.BigEndian.AppendUint16(nil, p.Port),
				})
			}
		} else if ipRangesPermitted.Len() > 0 || len(meta.PodSelectors) > 0 || len(peers) == 0 {
			// Set-based for complex port restrictions
			protoPortSet := nfds.Set{
				Table:         c.table,
				Anonymous:     true,
				Constant:      true,
				Concatenation: true,
				Interval:      true,
				KeyType:       nftables.MustConcatSetType(nftables.TypeInetProto, nftables.TypeInetService),
				KeyByteOrder:  binaryutil.BigEndian,
			}
			var setElems []nftables.SetElement
			for _, p := range portProtos {
				// uint8 protocol, uint16 port, both padded to 4 bytes, big endian
				startKey := make([]byte, 8)
				endKey := make([]byte, 8)
				startKey[0] = uint8(p.Protocol)
				endKey[0] = uint8(p.Protocol)
				binary.BigEndian.PutUint16(startKey[4:6], p.Port)
				binary.BigEndian.PutUint16(endKey[4:6], p.EndPort)
				setElems = append(setElems, nftables.SetElement{
					Key:    startKey,
					KeyEnd: endKey,
				})
			}

			c.nftConn.AddSet(&protoPortSet, setElems)
			portProtoExprs = []expr.Any{
				// Load L4 protocol into register 0
				&expr.Meta{
					Key:      expr.MetaKeyL4PROTO,
					Register: newRegOffset + 0,
				},
				// Load Port into register 1
				loadDstPort(1),
				// Abort if port/L4 protocol is not in permitted set
				lookup(Lookup{
					Set:            &protoPortSet,
					SourceRegister: newRegOffset + 0,
				}),
			}
		}
	}

	if ipRangesPermitted.Len() > 0 {
		exprs := []expr.Any{
			loadIP(dir, 0),
		}
		ipBlocksPermittedSet := nfds.Set{
			Table:        c.table,
			Anonymous:    true,
			Constant:     true,
			Interval:     true,
			KeyType:      nftables.TypeIPAddr,
			KeyType6:     nftables.TypeIP6Addr,
			KeyByteOrder: binaryutil.BigEndian,
		}
		var rangeElements []nftables.SetElement
		for it := ipRangesPermitted.Iterator(); it.Valid(); it.Next() {
			rangeElements = append(rangeElements, rangeToInterval(it.Item())...)
		}
		c.nftConn.AddSet(&ipBlocksPermittedSet, rangeElements)
		// Abort if address in register 0 is not in the permitted set
		exprs = append(exprs, lookup(Lookup{
			Set:            &ipBlocksPermittedSet,
			SourceRegister: newRegOffset + 0,
		}))

		exprs = append(exprs, portProtoExprs...)

		c.nftConn.AddRule(&nfds.Rule{
			Table: c.table,
			Chain: ch,
			Exprs: append(exprs, &expr.Verdict{ // Accept packet
				Kind: expr.VerdictAccept,
			}),
		})
	}
	if len(meta.PodSelectors) > 0 {
		podIPSet := nfds.Set{
			Table:        c.table,
			KeyType:      nftables.TypeIPAddr,
			KeyType6:     nftables.TypeIP6Addr,
			Name:         prefix + "_podips",
			KeyByteOrder: binaryutil.BigEndian,
		}
		c.nftConn.AddSet(&podIPSet, []nftables.SetElement{})
		meta.PodIPSet = &podIPSet
		exprs := []expr.Any{
			// Load IP address into register 0
			loadIP(dir, 0),
			// Check if IP is in pod IP set set
			lookup(Lookup{
				SourceRegister: newRegOffset + 0,
				Set:            &podIPSet,
			}),
		}
		exprs = append(exprs, portProtoExprs...)
		c.nftConn.AddRule(&nfds.Rule{
			Table: c.table,
			Chain: ch,
			Exprs: append(exprs, &expr.Verdict{Kind: expr.VerdictAccept}),
		})
	}
	if len(peers) == 0 {
		exprs := append([]expr.Any{}, portProtoExprs...)
		c.nftConn.AddRule(&nfds.Rule{
			Table: c.table,
			Chain: ch,
			Exprs: append(exprs, &expr.Verdict{Kind: expr.VerdictAccept}),
		})
	}
	return &meta
}

func (c *Controller) createNWP(name cache.ObjectName, policy *nwkv1.NetworkPolicy) {
	var nwp Policy
	var err error
	nwp.Namespace = policy.Namespace
	nwp.ID = objectID(&policy.ObjectMeta)
	nwp.PodSelector, err = metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
	if err != nil {
		c.eventRecorder.Eventf(policy, corev1.EventTypeWarning, "InvalidPolicy", "podSelector invalid: %v", err)
		return
	}

	var isIngress, isEgress bool
	if len(policy.Spec.PolicyTypes) == 0 {
		isIngress = true // K8s default if no PolicyTypes are present
		if len(policy.Spec.Egress) != 0 {
			isEgress = true
		}
	}
	for _, pt := range policy.Spec.PolicyTypes {
		if pt == nwkv1.PolicyTypeEgress {
			isEgress = true
		}
		if pt == nwkv1.PolicyTypeIngress {
			isIngress = true
		}
	}

	if isIngress {
		ingChain := nfds.Chain{
			Table: c.table,
			Type:  nftables.ChainTypeFilter,
			Name:  fmt.Sprintf("pol_%s_ing", nwp.ID),
		}
		c.nftConn.AddChain(&ingChain)
		for i, ingRule := range policy.Spec.Ingress {
			meta := c.createPeers(&ingChain, ingRule.From, ingRule.Ports, fmt.Sprintf("%s_%d", ingChain.Name, i), dirIngress, policy)
			for _, pod := range c.pods {
				c.addPodRule(meta, pod)
			}
			nwp.IngressRuleMeta = append(nwp.IngressRuleMeta, meta)
			c.rules[meta] = struct{}{}
		}
		nwp.ingressChain = &ingChain
	}
	if isEgress {
		egChain := nfds.Chain{
			Table: c.table,
			Type:  nftables.ChainTypeFilter,
			Name:  fmt.Sprintf("pol_%s_eg", nwp.ID),
		}
		c.nftConn.AddChain(&egChain)
		for i, egRule := range policy.Spec.Egress {
			meta := c.createPeers(&egChain, egRule.To, egRule.Ports, fmt.Sprintf("%s_%d", egChain.Name, i), dirEgress, policy)
			for _, pod := range c.pods {
				c.addPodRule(meta, pod)
			}
			nwp.EgressRuleMeta = append(nwp.EgressRuleMeta, meta)
			c.rules[meta] = struct{}{}
		}
		nwp.egressChain = &egChain
	}

	nwp.podRefs = make(map[*Pod]struct{})
	for _, pod := range c.pods {
		c.addPodNWP(pod, &nwp)
	}
	c.nwps[name] = &nwp
}

func (c *Controller) deleteRules(rm []*Rule) {
	for _, r := range rm {
		for p := range r.podRefs {
			delete(p.ruleRefs, r)
		}
		if r.NamedPortSet != nil {
			c.nftConn.DelSet(r.NamedPortSet)
		}
		if r.PodIPSet != nil {
			c.nftConn.DelSet(r.PodIPSet)
		}
		delete(c.rules, r)
	}
}

func (c *Controller) deleteNWP(name cache.ObjectName, nwp *Policy) {
	for p := range nwp.podRefs {
		c.removePodNWP(p, nwp)
	}
	if nwp.ingressChain != nil {
		c.nftConn.DelChain(nwp.ingressChain)
	}
	if nwp.egressChain != nil {
		c.nftConn.DelChain(nwp.egressChain)
	}
	c.deleteRules(nwp.IngressRuleMeta)
	c.deleteRules(nwp.EgressRuleMeta)
	delete(c.nwps, name)
}

func (c *Controller) SetNetworkPolicy(name cache.ObjectName, nwp *nwkv1.NetworkPolicy) {
	syncedNWP := c.nwps[name]
	switch {
	case syncedNWP == nil && nwp != nil:
		c.createNWP(name, nwp)
	case syncedNWP != nil && nwp == nil:
		// Delete NWP
		c.deleteNWP(name, syncedNWP)
	case syncedNWP != nil && nwp != nil:
		// Update NWP
		// TODO: Figure out if update is meaningful
		c.deleteNWP(name, syncedNWP)
		c.createNWP(name, nwp)
	case syncedNWP == nil && nwp == nil:
		// Nothing to do
	}
}
