package nftctrl

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type Namespace struct {
	Name   string
	Labels labels.Set
}

func (ns *Namespace) SemanticallyEqual(ns2 *Namespace) bool {
	if ns.Name != ns2.Name || len(ns.Labels) != len(ns2.Labels) {
		return false
	}
	for k, v := range ns.Labels {
		if v2, ok := ns2.Labels[k]; !ok || v2 != v {
			return false
		}
	}
	return true
}

func (c *Controller) updateNS(old, new *Namespace) {
	for r := range c.rules {
		reevalPods := make(map[*Pod]struct{})
		for _, sel := range r.PodSelectors {
			if sel.NamespaceSelector == labels.Nothing() {
				continue // Selector unaffected
			}
			var oldMatches bool
			if old != nil {
				oldMatches = sel.NamespaceSelector.Matches(old.Labels)
			}
			newMatches := sel.NamespaceSelector.Matches(new.Labels)
			if oldMatches == newMatches {
				continue // Selector unaffected by change
			}
			// Relevant change happened, compute pods changed
			if oldMatches {
				for pod := range r.podRefs {
					if pod.Namespace == new.Name {
						reevalPods[pod] = struct{}{}
					}
				}
			} else {
				for _, pod := range c.pods {
					if pod.Namespace == new.Name {
						reevalPods[pod] = struct{}{}
					}
				}
			}
		}
		for p := range reevalPods {
			c.reevalPodInRule(p, r)
		}
	}
}

func (c *Controller) reevalPodInRule(pm *Pod, r *Rule) {
	for _, sel := range r.PodSelectors {
		if !sel.Matches(pm, r.Namespace, c.namespaces) {
			continue
		}
		if _, ok := r.podRefs[pm]; ok {
			break
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
		return
	}
	if _, ok := r.podRefs[pm]; ok {
		// Pod was previously selected but is no more, remove it from the rule
		delete(r.podRefs, pm)
		delete(pm.ruleRefs, r)
		if r.PodIPSet != nil {
			c.nftConn.SetDeleteElements(r.PodIPSet, pm.ipElements())
		}
		if r.NamedPortSet != nil {
			c.nftConn.SetDeleteElements(r.NamedPortSet, pm.namedPortElements(r.NamedPortMeta))
		}
	}
}

func (c *Controller) SetNamespace(name string, ns *corev1.Namespace) {
	syncedNS := c.namespaces[name]
	switch {
	case syncedNS == nil && ns != nil:
		c.namespaces[name] = &Namespace{
			Name:   name,
			Labels: ns.Labels,
		}
		c.updateNS(nil, c.namespaces[name])
	case syncedNS != nil && ns == nil:
		delete(c.namespaces, name)
	case syncedNS != nil && ns != nil:
		newNS := &Namespace{
			Name:   name,
			Labels: ns.Labels,
		}
		if syncedNS.SemanticallyEqual(newNS) {
			return // Nothing to do
		}
		c.namespaces[name] = newNS
		c.updateNS(syncedNS, newNS)
	case syncedNS == nil && ns == nil:
		// Nothing to do
	}
}