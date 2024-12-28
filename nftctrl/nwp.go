package nftctrl

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"git.dolansoft.org/lorenz/k8s-nft-npc/nfds"
	"git.dolansoft.org/lorenz/k8s-nft-npc/ranges"
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
	Name            string
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

func (sel PodSelector) Matches(pm *Pod, selNs string, namespaces map[string]*Namespace) bool {
	if sel.NamespaceSelector == labels.Nothing() && selNs != pm.Namespace {
		return false
	}
	if namespaces[pm.Namespace] == nil {
		return false
	}
	if sel.NamespaceSelector != labels.Nothing() && !sel.NamespaceSelector.Matches(namespaces[pm.Namespace].Labels) {
		return false
	}
	if !sel.PodSelector.Matches(pm.Labels) {
		return false
	}
	return true
}

func (c *Controller) createPeers(ch *nfds.Chain, peers []nwkv1.NetworkPolicyPeer, ports []nwkv1.NetworkPolicyPort, prefix string, dir direction, nwp *nwkv1.NetworkPolicy) (*Rule, error) {
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
			switch *port.Protocol {
			case corev1.ProtocolTCP:
				proto = unix.IPPROTO_TCP
			case corev1.ProtocolUDP:
				proto = unix.IPPROTO_UDP
			case corev1.ProtocolSCTP:
				proto = unix.IPPROTO_SCTP
			default:
				c.eventRecorder.Eventf(nwp, corev1.EventTypeWarning, "InvalidPort", "port protocol %q unknown, ignoring port", *port.Protocol)
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
	if len(dynPorts) > 0 && len(meta.PodSelectors) > 0 {
		namedPortSet := nfds.Set{
			Table:         c.table,
			Name:          prefix + "_namedports",
			KeyType:       nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeInetProto, nftables.TypeInetService),
			KeyType6:      nftables.MustConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetProto, nftables.TypeInetService),
			Concatenation: true,
		}
		c.nftConn.AddSet(&namedPortSet, []nftables.SetElement{})
		meta.NamedPortSet = &namedPortSet
		meta.NamedPortMeta = dynPorts
		c.nftConn.AddRule(&nfds.Rule{
			Table: c.table,
			Chain: ch,
			Exprs: []expr.Any{
				// Load IP address into register 0
				loadIP(dir, 0),
				// Load Layer 4 protocol into register 2
				&expr.Meta{
					Key:      expr.MetaKeyL4PROTO,
					Register: newRegOffset + 4,
				},
				// Load Port into register 5
				loadDstPort(5),
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
		return &meta, nil
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
		} else if ipRangesPermitted.Len() > 0 || len(meta.PodSelectors) > 0 { // Set-based for complex port restrictions
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
	return &meta, nil
}

func (c *Controller) createNWP(nwp *nwkv1.NetworkPolicy, name cache.ObjectName) (*Policy, error) {
	var pm Policy
	var err error
	pm.Namespace = nwp.Namespace
	pm.Name = nwp.Name
	pm.PodSelector, err = metav1.LabelSelectorAsSelector(&nwp.Spec.PodSelector)
	if err != nil {
		return nil, fmt.Errorf("bad PodSelector: %w", err)
	}

	var isIngress, isEgress bool
	if len(nwp.Spec.PolicyTypes) == 0 {
		isIngress = true // K8s default if no PolicyTypes are present
	}
	for _, pt := range nwp.Spec.PolicyTypes {
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
			Name:  fmt.Sprintf("pol_%v_%v_ing", pm.Namespace, pm.Name),
		}
		c.nftConn.AddChain(&ingChain)
		for i, ingRule := range nwp.Spec.Ingress {
			meta, err := c.createPeers(&ingChain, ingRule.From, ingRule.Ports, fmt.Sprintf("%v_%d", ingChain.Name, i), dirIngress, nwp)
			if err != nil {
				return nil, fmt.Errorf("failed to create ingress peer rules: %w", err)
			}
			for _, pod := range c.pods {
				c.addPodRule(meta, pod)
			}
			pm.IngressRuleMeta = append(pm.IngressRuleMeta, meta)
			c.rules[meta] = struct{}{}
		}
		c.nftConn.AddRule(&nfds.Rule{
			Table: c.table,
			Chain: &ingChain,
			Exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictReturn},
			},
		})
		pm.ingressChain = &ingChain
	}
	if isEgress {
		egChain := nfds.Chain{
			Table: c.table,
			Type:  nftables.ChainTypeFilter,
			Name:  fmt.Sprintf("pol_%v_%v_eg", pm.Namespace, pm.Name),
		}
		c.nftConn.AddChain(&egChain)
		for i, egRule := range nwp.Spec.Egress {
			meta, err := c.createPeers(&egChain, egRule.To, egRule.Ports, fmt.Sprintf("%v_%d", egChain.Name, i), dirEgress, nwp)
			if err != nil {
				return nil, fmt.Errorf("failed to create egress peer rules: %w", err)
			}
			for _, pod := range c.pods {
				c.addPodRule(meta, pod)
			}
			pm.EgressRuleMeta = append(pm.EgressRuleMeta, meta)
			c.rules[meta] = struct{}{}
		}
		c.nftConn.AddRule(&nfds.Rule{
			Table: c.table,
			Chain: &egChain,
			Exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictReturn},
			},
		})
		pm.egressChain = &egChain
	}

	pm.podRefs = make(map[*Pod]struct{})
	for _, pod := range c.pods {
		c.addPodNWP(&pm, pod)
	}
	c.nwps[name] = &pm
	return &pm, nil
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

func (c *Controller) deleteNWP(pm *Policy, name cache.ObjectName) {
	for p := range pm.podRefs {
		c.removePodNWP(p, pm)
	}
	if pm.ingressChain != nil {
		c.nftConn.DelChain(pm.ingressChain)
	}
	if pm.egressChain != nil {
		c.nftConn.DelChain(pm.egressChain)
	}
	c.deleteRules(pm.IngressRuleMeta)
	c.deleteRules(pm.EgressRuleMeta)
	delete(c.nwps, name)
}

func (c *Controller) SetNetworkPolicy(name cache.ObjectName, nwp *nwkv1.NetworkPolicy) error {
	syncedNWP := c.nwps[name]
	switch {
	case syncedNWP == nil && nwp != nil:
		c.createNWP(nwp, name)
	case syncedNWP != nil && nwp == nil:
		// Delete NWP
		c.deleteNWP(syncedNWP, name)
	case syncedNWP != nil && nwp != nil:
		// Update NWP
		// TODO: Figure out if update is meaningful
		c.deleteNWP(syncedNWP, name)
		c.createNWP(nwp, name)
	case syncedNWP == nil && nwp == nil:
		// Nothing to do
	}
	return nil
}
