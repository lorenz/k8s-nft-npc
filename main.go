package main

import (
	"context"
	"flag"
	"os"
	"os/signal"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	cv1if "k8s.io/client-go/informers/core/v1"
	nwkv1if "k8s.io/client-go/informers/networking/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/cache/synctrack"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/kubectl/pkg/scheme"

	"git.dolansoft.org/lorenz/k8s-nft-npc/nftctrl"
)

var (
	masterURL = flag.String("master", "",
		"The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	kubeconfig = flag.String("kubeconfig", "",
		"Path to a kubeconfig. Only required if out-of-cluster.")
	podIfaceGroup = flag.Uint("pod-interface-group", 0, "Interface group id for pod-facing interfaces. Recommended in most use cases, required if the nodes also act as routers for non-local traffic.")
)

type Controller struct {
	nft             *nftctrl.Controller
	informerFactory informers.SharedInformerFactory
	podInformer     cv1if.PodInformer
	nsInformer      cv1if.NamespaceInformer
	nwpInformer     nwkv1if.NetworkPolicyInformer

	q            workqueue.TypedRateLimitingInterface[workItem]
	hasProcessed synctrack.AsyncTracker[workItem]

	eventRecorder record.EventRecorder
}

type workItem struct {
	typ  string
	name cache.ObjectName
}

type updateEnqueuer struct {
	typ          string
	q            workqueue.TypedRateLimitingInterface[workItem]
	hasProcessed *synctrack.AsyncTracker[workItem]
}

func (c *updateEnqueuer) OnAdd(obj interface{}, isInInitialList bool) {
	name, err := cache.ObjectToName(obj)
	if err != nil {
		klog.Warningf("OnAdd name for type %q cannot be derived: %v", c.typ, err)
	}
	item := workItem{typ: c.typ, name: name}
	c.q.Add(item)
	if isInInitialList {
		c.hasProcessed.Start(item)
	}
}

func (c *updateEnqueuer) OnUpdate(oldObj, newObj interface{}) {
	name, err := cache.ObjectToName(newObj)
	if err != nil {
		klog.Warningf("OnAdd name for type %q cannot be derived: %v", c.typ, err)
	}
	c.q.Add(workItem{typ: c.typ, name: name})
}

func (c *updateEnqueuer) OnDelete(obj interface{}) {
	name, err := cache.DeletionHandlingObjectToName(obj)
	if err != nil {
		klog.Warningf("OnAdd name for type %q cannot be derived: %v", c.typ, err)
		return
	}
	c.q.Add(workItem{typ: c.typ, name: name})
}

func (c *Controller) worker() {
	for {
		i, shut := c.q.Get()
		switch i.typ {
		case "pod":
			pod, _ := c.podInformer.Lister().Pods(i.name.Namespace).Get(i.name.Name)
			klog.Infof("Syncing pod %v", i.name)
			c.nft.SetPod(i.name, pod)
			c.q.Done(i)
			if c.hasProcessed.HasSynced() {
				if err := c.nft.Flush(); err != nil {
					klog.Warningf("Failed to flush pod %v: %v", i.name, err)
				}
			}
			c.hasProcessed.Finished(i)
		case "nwp":
			nwp, _ := c.nwpInformer.Lister().NetworkPolicies(i.name.Namespace).Get(i.name.Name)
			klog.Infof("Syncing NWP %v", i.name)
			if err := c.nft.SetNetworkPolicy(i.name, nwp); err == nil {
				c.q.Forget(i)
			} else {
				klog.Warningf("SetNetworkPolicy error, requeuing: %v", err)
				c.q.AddRateLimited(i)
			}
			c.q.Done(i)
			if c.hasProcessed.HasSynced() {
				if err := c.nft.Flush(); err != nil {
					klog.Warningf("Failed to flush nwp %v: %v", i.name, err)
				}
			}
			c.hasProcessed.Finished(i)
		case "ns":
			// We assume that K8s will delete all resources in a namespace
			// that is going away
			klog.Infof("Syncing NS %v", i.name)
			ns, _ := c.nsInformer.Lister().Get(i.name.Name)
			c.nft.SetNamespace(i.name.Name, ns)
			c.q.Done(i)
			if c.hasProcessed.HasSynced() {
				if err := c.nft.Flush(); err != nil {
					klog.Warningf("Failed to flush ns %v: %v", i.name.Name, err)
				}
			}
			c.hasProcessed.Finished(i)
		default:
			c.q.Done(i)
		}
		if shut {
			return
		}
	}
}

func main() {
	flag.Parse()

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)

	cfg, err := clientcmd.BuildConfigFromFlags(*masterURL, *kubeconfig)
	if err != nil {
		klog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.Fatalf("Error building kubernetes clientset: %s", err.Error())
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})

	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "npc"})

	c := Controller{
		nft:           nftctrl.New(recorder, uint32(*podIfaceGroup)),
		eventRecorder: recorder,
	}

	c.informerFactory = informers.NewSharedInformerFactory(kubeClient, 0)
	c.q = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[workItem]())

	c.nsInformer = c.informerFactory.Core().V1().Namespaces()
	nsHandler, _ := c.nsInformer.Informer().AddEventHandler(&updateEnqueuer{q: c.q, typ: "ns", hasProcessed: &c.hasProcessed})
	c.podInformer = c.informerFactory.Core().V1().Pods()
	podHandler, _ := c.podInformer.Informer().AddEventHandler(&updateEnqueuer{q: c.q, typ: "pod", hasProcessed: &c.hasProcessed})
	c.nwpInformer = c.informerFactory.Networking().V1().NetworkPolicies()
	nwpHandler, _ := c.nwpInformer.Informer().AddEventHandler(&updateEnqueuer{q: c.q, typ: "nwp", hasProcessed: &c.hasProcessed})
	c.hasProcessed.UpstreamHasSynced = func() bool {
		return nsHandler.HasSynced() && podHandler.HasSynced() && nwpHandler.HasSynced()
	}
	c.informerFactory.Start(ctx.Done())

	klog.Info("Starting k8s-nft-npc worker")
	go c.worker()

	cache.WaitForNamedCacheSync("k8s-nft-npc", ctx.Done(), c.hasProcessed.HasSynced)
	if err := c.nft.Flush(); err != nil { // Flush once after enabling
		klog.Errorf("Initial flush failed: %v", err)
	}
	<-ctx.Done()
	klog.Warning("Received signal, shutting down")
	c.q.ShutDown()
}
