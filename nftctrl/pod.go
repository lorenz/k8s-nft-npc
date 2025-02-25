package nftctrl

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"git.dolansoft.org/dolansoft/k8s-nft-npc/nfds"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type Pod struct {
	Namespace  string
	ID         string
	Labels     labels.Set
	IPs        []netip.Addr
	NamedPorts map[string]NamedPort

	ingressChain, egressChain *nfds.Chain

	ruleRefs map[*Rule]struct{}

	ingressPolicyRefs, egressPolicyRefs map[*Policy]*nfds.Rule
}

type NamedPort struct {
	Protocol uint8
	Port     uint16
}

func (p *Pod) vmapElements(chain *nfds.Chain) []nftables.SetElement {
	var elems []nftables.SetElement
	for _, ip := range p.IPs {
		elems = append(elems, nftables.SetElement{
			Key: ip.AsSlice(),
			VerdictData: &expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: chain.Name,
			},
		})
	}
	return elems
}

func (p *Pod) ipElements() []nftables.SetElement {
	var elems []nftables.SetElement
	for _, ip := range p.IPs {
		elems = append(elems, nftables.SetElement{
			Key: ip.AsSlice(),
		})
	}
	return elems
}

func (p *Pod) namedPortElements(nms []RuleNamedPortMeta) []nftables.SetElement {
	var elems []nftables.SetElement
	for _, ip := range p.IPs {
		for _, nm := range nms {
			port, ok := p.NamedPorts[nm.PortName]
			if !ok || port.Protocol != nm.Protocol {
				continue
			}
			elems = append(elems, nftables.SetElement{
				Key: append(append(binary.BigEndian.AppendUint16([]byte{nm.Protocol, 0, 0, 0}, port.Port), 0, 0), ip.AsSlice()...),
			})
		}
	}
	return elems
}

func (p *Pod) SemanticallyEqual(p2 *Pod) bool {
	if p.Namespace != p2.Namespace || p.ID != p2.ID || len(p.Labels) != len(p2.Labels) || len(p.IPs) != len(p2.IPs) || len(p.NamedPorts) != len(p2.NamedPorts) {
		return false
	}
	for k, v1 := range p.Labels {
		if v2, ok := p2.Labels[k]; !ok || v1 != v2 {
			return false
		}
	}
	for n, p := range p.NamedPorts {
		if p2, ok := p2.NamedPorts[n]; !ok || p2 != p {
			return false
		}
	}
	ipSet := make(map[netip.Addr]struct{})
	for _, ip := range p2.IPs {
		ipSet[ip] = struct{}{}
	}
	for _, ip := range p.IPs {
		if _, ok := ipSet[ip]; !ok {
			return false
		}
	}
	return true
}

func (c *Controller) addPodNWP(p *Pod, nwp *Policy) {
	if nwp.Namespace != p.Namespace || !nwp.PodSelector.Matches(p.Labels) {
		return
	}
	if nwp.ingressChain != nil {
		if p.ingressChain == nil {
			p.ingressChain = c.nftConn.AddChain(&nfds.Chain{
				Name:  fmt.Sprintf("pod_%s_ing", p.ID),
				Table: c.table,
				Type:  nftables.ChainTypeFilter,
			})
			c.nftConn.AddRule(&nfds.Rule{
				Table: c.table,
				Chain: p.ingressChain,
				Exprs: []expr.Any{
					// Reject everything not permitted directly by a network policy or
					// related to a connection permitted by it.
					rejectAdministrative(),
				},
			})
			if err := c.nftConn.SetAddElements(c.vmapIng, p.vmapElements(p.ingressChain)); err != nil {
				panic(err)
			}
		}
		p.ingressPolicyRefs[nwp] = c.nftConn.InsertRule(&nfds.Rule{
			Table: c.table,
			Chain: p.ingressChain,
			Exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictJump, Chain: nwp.ingressChain.Name},
			},
		})
		nwp.podRefs[p] = struct{}{}
	}
	if nwp.egressChain != nil {
		if p.egressChain == nil {
			p.egressChain = c.nftConn.AddChain(&nfds.Chain{
				Name:  fmt.Sprintf("pod_%s_eg", p.ID),
				Table: c.table,
				Type:  nftables.ChainTypeFilter,
			})
			c.nftConn.AddRule(&nfds.Rule{
				Table: c.table,
				Chain: p.egressChain,
				Exprs: []expr.Any{
					// Reject everything not permitted directly by a network policy or
					// related to a connection permitted by it.
					rejectAdministrative(),
				},
			})

			if err := c.nftConn.SetAddElements(c.vmapEg, p.vmapElements(p.egressChain)); err != nil {
				panic(err)
			}
		}
		p.egressPolicyRefs[nwp] = c.nftConn.InsertRule(&nfds.Rule{
			Table: c.table,
			Chain: p.egressChain,
			Exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictJump, Chain: nwp.egressChain.Name},
			},
		})
		nwp.podRefs[p] = struct{}{}
	}
}

func (c *Controller) removePodNWP(p *Pod, nwp *Policy) {
	r, ok := p.ingressPolicyRefs[nwp]
	if r != nil {
		c.nftConn.DelRule(r)
	}
	if ok {
		delete(p.ingressPolicyRefs, nwp)
	}
	if len(p.ingressPolicyRefs) == 0 && p.ingressChain != nil {
		c.nftConn.SetDeleteElements(c.vmapIng, p.vmapElements(p.ingressChain))
		c.nftConn.DelChain(p.ingressChain)
		p.ingressChain = nil
	}

	r, ok = p.egressPolicyRefs[nwp]
	if r != nil {
		c.nftConn.DelRule(r)
	}
	if ok {
		delete(p.egressPolicyRefs, nwp)
	}
	if len(p.egressPolicyRefs) == 0 && p.egressChain != nil {
		c.nftConn.SetDeleteElements(c.vmapEg, p.vmapElements(p.egressChain))
		c.nftConn.DelChain(p.egressChain)
		p.egressChain = nil
	}
}

func (c *Controller) ruleSelectsPod(r *Rule, p *Pod) bool {
	for _, sel := range r.PodSelectors {
		if sel.Matches(p, r.Namespace, c.namespaces) {
			return true
		}
	}
	// Rules with named ports but no peer restriction select all pods.
	return len(r.PodSelectors) == 0 && r.NamedPortSet != nil
}

func (c *Controller) addPodRule(r *Rule, p *Pod) {
	if c.ruleSelectsPod(r, p) {
		p.ruleRefs[r] = struct{}{}
		r.podRefs[p] = struct{}{}
		if r.PodIPSet != nil {
			c.nftConn.SetAddElements(r.PodIPSet, p.ipElements())
		}
		if r.NamedPortSet != nil {
			c.nftConn.SetAddElements(r.NamedPortSet, p.namedPortElements(r.NamedPortMeta))
		}
	}
}

func (c *Controller) deletePod(p *Pod) {
	if p.ingressChain != nil {
		c.nftConn.SetDeleteElements(c.vmapIng, p.vmapElements(p.ingressChain))
		c.nftConn.DelChain(p.ingressChain)
	}
	for nwp := range p.ingressPolicyRefs {
		delete(nwp.podRefs, p)
	}

	if p.egressChain != nil {
		c.nftConn.SetDeleteElements(c.vmapEg, p.vmapElements(p.egressChain))
		c.nftConn.DelChain(p.egressChain)
	}
	for nwp := range p.egressPolicyRefs {
		delete(nwp.podRefs, p)
	}
	for r := range p.ruleRefs {
		delete(r.podRefs, p)
		if r.PodIPSet != nil {
			c.nftConn.SetDeleteElements(r.PodIPSet, p.ipElements())
		}
		if r.NamedPortSet != nil {
			c.nftConn.SetDeleteElements(r.NamedPortSet, p.namedPortElements(r.NamedPortMeta))
		}
	}
}

func (c *Controller) SetPod(name cache.ObjectName, pod *corev1.Pod) {
	syncedPod := c.pods[name]
	switch {
	case syncedPod == nil && pod != nil:
		p := c.normalizePod(pod)
		for _, nwp := range c.nwps {
			c.addPodNWP(p, nwp)
		}
		for r := range c.rules {
			c.addPodRule(r, p)
		}
		c.pods[name] = p
	case syncedPod != nil && pod == nil:
		c.deletePod(syncedPod)
		delete(c.pods, name)
	case syncedPod != nil && pod != nil:
		// Update Pod
		p := c.normalizePod(pod)
		if p.SemanticallyEqual(syncedPod) {
			return // Nothing to do
		}
		// Recreate, we curently cannot intelligently update
		c.deletePod(syncedPod)
		delete(c.pods, name)
		for _, nwp := range c.nwps {
			c.addPodNWP(p, nwp)
		}
		for r := range c.rules {
			c.addPodRule(r, p)
		}
		c.pods[name] = p
	case syncedPod == nil && pod == nil:
		// Nothing to do
	}
}

func (c *Controller) normalizePod(pod *corev1.Pod) *Pod {
	var p Pod
	p.Namespace = pod.Namespace
	p.ID = objectID(&pod.ObjectMeta)
	p.Labels = pod.Labels
	for _, ip := range pod.Status.PodIPs {
		if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
			continue
		}
		pIP, err := netip.ParseAddr(ip.IP)
		if err != nil {
			klog.Warningf("Failed to parse IP %q of pod %q: %v", ip.IP, p.ID, err)
			continue
		}
		p.IPs = append(p.IPs, pIP)
	}
	p.NamedPorts = make(map[string]NamedPort)
	p.ruleRefs = make(map[*Rule]struct{})
	p.egressPolicyRefs = make(map[*Policy]*nfds.Rule)
	p.ingressPolicyRefs = make(map[*Policy]*nfds.Rule)
	for _, containers := range [][]corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for _, container := range containers {
			for _, port := range container.Ports {
				if port.Name != "" {
					if port.ContainerPort > math.MaxUint16 {
						c.eventRecorder.Eventf(pod, corev1.EventTypeWarning, "InvalidPort", "Container %v port %v is out of range, ignore", container.Name, port.ContainerPort)
						continue
					}
					var proto uint8 = unix.IPPROTO_TCP
					if port.Protocol != "" {
						var ok bool
						proto, ok = parseProtocol(port.Protocol)
						if !ok {
							// Ignore unknown protocol without logging. We already log unknown
							// protocols in policies, and as long as no policy mentions a
							// protocol, it doesn't matter whether we support it.
							continue
						}
					}
					p.NamedPorts[port.Name] = NamedPort{
						Protocol: proto,
						Port:     uint16(port.ContainerPort),
					}
				}
			}
		}
	}
	return &p
}

func parseProtocol(protocol corev1.Protocol) (proto uint8, ok bool) {
	switch protocol {
	case corev1.ProtocolTCP:
		return unix.IPPROTO_TCP, true
	case corev1.ProtocolUDP:
		return unix.IPPROTO_UDP, true
	case corev1.ProtocolSCTP:
		return unix.IPPROTO_SCTP, true
	default:
		return 0, false
	}
}
