package nftctrl

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"git.dolansoft.org/lorenz/k8s-nft-npc/nfds"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type Pod struct {
	Namespace  string
	Name       string
	Labels     labels.Set
	IPs        []netip.Addr
	NamedPorts map[string]uint16

	ingressChain, egressChain *nfds.Chain

	ruleRefs map[*Rule]struct{}

	ingressPolicyRefs, egressPolicyRefs map[*Policy]*nfds.Rule
}

func (pm *Pod) vmapElements(chain *nfds.Chain) []nftables.SetElement {
	var elems []nftables.SetElement
	for _, ip := range pm.IPs {
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

func (pm *Pod) ipElements() []nftables.SetElement {
	var elems []nftables.SetElement
	for _, ip := range pm.IPs {
		elems = append(elems, nftables.SetElement{
			Key: ip.AsSlice(),
		})
	}
	return elems
}

func (pm *Pod) namedPortElements(nms []RuleNamedPortMeta) []nftables.SetElement {
	var elems []nftables.SetElement
	for _, ip := range pm.IPs {
		for _, nm := range nms {
			// TODO: Protocols
			portNum, ok := pm.NamedPorts[nm.PortName]
			if !ok {
				continue
			}
			elems = append(elems, nftables.SetElement{
				Key: binary.NativeEndian.AppendUint16(append(ip.AsSlice(), 0, 0, 0, nm.Protocol, 0, 0), portNum),
			})
		}
	}
	return elems
}

func (pm *Pod) SemanticallyEqual(pm2 *Pod) bool {
	if pm.Namespace != pm2.Namespace || pm.Name != pm2.Name || len(pm.Labels) != len(pm2.Labels) || len(pm.IPs) != len(pm2.IPs) || len(pm.NamedPorts) != len(pm2.NamedPorts) {
		return false
	}
	for k, v1 := range pm.Labels {
		if v2, ok := pm2.Labels[k]; !ok || v1 != v2 {
			return false
		}
	}
	for n, p := range pm.NamedPorts {
		if p2, ok := pm2.NamedPorts[n]; !ok || p2 != p {
			return false
		}
	}
	ipSet := make(map[netip.Addr]struct{})
	for _, ip := range pm2.IPs {
		ipSet[ip] = struct{}{}
	}
	for _, ip := range pm.IPs {
		if _, ok := ipSet[ip]; !ok {
			return false
		}
	}
	return true
}

func (c *Controller) addPodNWP(nwp *Policy, pm *Pod) {
	if nwp.Namespace != pm.Namespace || !nwp.PodSelector.Matches(pm.Labels) {
		return
	}
	if nwp.ingressChain != nil {
		if pm.ingressChain == nil {
			pm.ingressChain = c.nftConn.AddChain(&nfds.Chain{
				Name:  fmt.Sprintf("pod_%s_%s_ing", pm.Namespace, pm.Name),
				Table: c.table,
				Type:  nftables.ChainTypeFilter,
			})
			c.nftConn.AddRule(&nfds.Rule{
				Table: c.table,
				Chain: pm.ingressChain,
				Exprs: []expr.Any{
					// Accept packets for established or related connections
					&expr.Ct{Key: expr.CtKeySTATE, Register: newRegOffset + 1},
					&expr.Bitwise{SourceRegister: newRegOffset + 1, DestRegister: newRegOffset + 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: binaryutil.NativeEndian.PutUint32(0)},
					&expr.Cmp{Op: expr.CmpOpNeq, Register: newRegOffset + 1, Data: binaryutil.NativeEndian.PutUint32(0)},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
			c.nftConn.AddRule(&nfds.Rule{
				Table: c.table,
				Chain: pm.ingressChain,
				Exprs: []expr.Any{
					// Reject everything not permitted directly by a network policy or
					// related to a connection permitted by it.
					rejectAdministrative(),
				},
			})
			if err := c.nftConn.SetAddElements(c.vmapIng, pm.vmapElements(pm.ingressChain)); err != nil {
				panic(err)
			}
		}
		pm.ingressPolicyRefs[nwp] = c.nftConn.InsertRule(&nfds.Rule{
			Table: c.table,
			Chain: pm.ingressChain,
			Exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictJump, Chain: nwp.ingressChain.Name},
			},
		})
		nwp.podRefs[pm] = struct{}{}
	}
	if nwp.egressChain != nil {
		if pm.egressChain == nil {
			pm.egressChain = c.nftConn.AddChain(&nfds.Chain{
				Name:  fmt.Sprintf("pod_%s_%s_eg", pm.Namespace, pm.Name),
				Table: c.table,
				Type:  nftables.ChainTypeFilter,
			})
			c.nftConn.AddRule(&nfds.Rule{
				Table: c.table,
				Chain: pm.egressChain,
				Exprs: []expr.Any{
					// Accept packets for established or related connections
					&expr.Ct{Key: expr.CtKeySTATE, Register: newRegOffset + 1},
					&expr.Bitwise{SourceRegister: newRegOffset + 1, DestRegister: newRegOffset + 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: binaryutil.NativeEndian.PutUint32(0)},
					&expr.Cmp{Op: expr.CmpOpNeq, Register: newRegOffset + 1, Data: binaryutil.NativeEndian.PutUint32(0)},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
			c.nftConn.AddRule(&nfds.Rule{
				Table: c.table,
				Chain: pm.egressChain,
				Exprs: []expr.Any{
					// Reject everything not permitted directly by a network policy or
					// related to a connection permitted by it.
					rejectAdministrative(),
				},
			})

			if err := c.nftConn.SetAddElements(c.vmapEg, pm.vmapElements(pm.egressChain)); err != nil {
				panic(err)
			}
		}
		pm.egressPolicyRefs[nwp] = c.nftConn.InsertRule(&nfds.Rule{
			Table: c.table,
			Chain: pm.egressChain,
			Exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictJump, Chain: nwp.egressChain.Name},
			},
		})
		nwp.podRefs[pm] = struct{}{}
	}
}

func (c *Controller) removePodNWP(p *Pod, pm *Policy) {
	r, ok := p.ingressPolicyRefs[pm]
	if r != nil {
		c.nftConn.DelRule(r)
	}
	if ok {
		delete(p.ingressPolicyRefs, pm)
	}
	if len(p.ingressPolicyRefs) == 0 && p.ingressChain != nil {
		c.nftConn.SetDeleteElements(c.vmapIng, p.vmapElements(p.ingressChain))
		c.nftConn.DelChain(p.ingressChain)
		p.ingressChain = nil
	}

	r, ok = p.egressPolicyRefs[pm]
	if r != nil {
		c.nftConn.DelRule(r)
	}
	if ok {
		delete(p.egressPolicyRefs, pm)
	}
	if len(p.egressPolicyRefs) == 0 && p.egressChain != nil {
		c.nftConn.SetDeleteElements(c.vmapEg, p.vmapElements(p.egressChain))
		c.nftConn.DelChain(p.egressChain)
		p.egressChain = nil
	}
}

func (c *Controller) addPodRule(r *Rule, pm *Pod) {
	for _, sel := range r.PodSelectors {
		if !sel.Matches(pm, r.Namespace, c.namespaces) {
			continue
		}
		pm.ruleRefs[r] = struct{}{}
		r.podRefs[pm] = struct{}{}
		if r.PodIPSet != nil {
			c.nftConn.SetAddElements(r.PodIPSet, pm.ipElements())
		}
		if r.NamedPortSet != nil {
			c.nftConn.SetAddElements(r.NamedPortSet, pm.namedPortElements(r.NamedPortMeta))
		}
		// Pod got selected by at least one selector, more do not change anything
		break
	}
}

func (c *Controller) deletePod(pm *Pod) error {
	if pm.ingressChain != nil {
		c.nftConn.SetDeleteElements(c.vmapIng, pm.vmapElements(pm.ingressChain))
		c.nftConn.DelChain(pm.ingressChain)
	}
	for p := range pm.ingressPolicyRefs {
		delete(p.podRefs, pm)
	}

	if pm.egressChain != nil {
		c.nftConn.SetDeleteElements(c.vmapEg, pm.vmapElements(pm.egressChain))
		c.nftConn.DelChain(pm.egressChain)
	}
	for p := range pm.egressPolicyRefs {
		delete(p.podRefs, pm)
	}
	for r := range pm.ruleRefs {
		delete(r.podRefs, pm)
		if r.PodIPSet != nil {
			c.nftConn.SetDeleteElements(r.PodIPSet, pm.ipElements())
		}
		if r.NamedPortSet != nil {
			c.nftConn.SetDeleteElements(r.NamedPortSet, pm.namedPortElements(r.NamedPortMeta))
		}
	}
	return nil
}

func (c *Controller) SetPod(name cache.ObjectName, pod *corev1.Pod) {
	syncedPod := c.pods[name]
	switch {
	case syncedPod == nil && pod != nil:
		np := c.normalizePod(pod)
		for _, nwp := range c.nwps {
			c.addPodNWP(nwp, np)
		}
		for r := range c.rules {
			c.addPodRule(r, np)
		}
		c.pods[name] = np
	case syncedPod != nil && pod == nil:
		c.deletePod(syncedPod)
		delete(c.pods, name)
	case syncedPod != nil && pod != nil:
		// Update Pod
		np := c.normalizePod(pod)
		if np.SemanticallyEqual(syncedPod) {
			return // Nothing to do
		}
		// Recreate, we curently cannot intelligently update
		c.deletePod(syncedPod)
		delete(c.pods, name)
		for _, nwp := range c.nwps {
			c.addPodNWP(nwp, np)
		}
		for r := range c.rules {
			c.addPodRule(r, np)
		}
		c.pods[name] = np
	case syncedPod == nil && pod == nil:
		// Nothing to do
	}
}

func (c *Controller) normalizePod(pod *corev1.Pod) *Pod {
	var p Pod
	p.Namespace = pod.Namespace
	p.Name = pod.Name
	p.Labels = pod.Labels
	for _, ip := range pod.Status.PodIPs {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		pIP, err := netip.ParseAddr(ip.IP)
		if err != nil {
			klog.Warningf("Failed to parse IP %q of pod %q: %v", ip.IP, p.Name, err)
			continue
		}
		p.IPs = append(p.IPs, pIP)
	}
	p.NamedPorts = make(map[string]uint16)
	p.ruleRefs = make(map[*Rule]struct{})
	p.egressPolicyRefs = make(map[*Policy]*nfds.Rule)
	p.ingressPolicyRefs = make(map[*Policy]*nfds.Rule)
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name != "" {
				if port.ContainerPort > math.MaxUint16 {
					c.eventRecorder.Eventf(pod, corev1.EventTypeWarning, "InvalidPort", "Container %v port %v is out of range, ignore", container.Name, port.ContainerPort)
					continue
				}
				p.NamedPorts[port.Name] = uint16(port.ContainerPort)
			}
		}
	}
	for _, container := range pod.Spec.InitContainers {
		for _, port := range container.Ports {
			if port.Name != "" {
				if port.ContainerPort > math.MaxUint16 {
					c.eventRecorder.Eventf(pod, corev1.EventTypeWarning, "InvalidPort", "Container %v port %v is out of range, ignore", container.Name, port.ContainerPort)
					continue
				}
				p.NamedPorts[port.Name] = uint16(port.ContainerPort)
			}
		}
	}
	return &p
}
