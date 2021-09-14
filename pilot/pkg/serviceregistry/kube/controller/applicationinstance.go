package controller

import (
	"fmt"
	"sync"

	appsv1 "tess.io/ebay/api/apps/v1alpha2"
	appsinformers "tess.io/ebay/client-go/informers/apps/v1alpha2"

	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube"
	"istio.io/istio/pilot/pkg/util/sets"
	"istio.io/pkg/monitoring"
)

var (
	svcPendingAppInstUpdate = monitoring.NewGauge(
		"pilot_k8s_service_pending_application_instance",
		"Number of service that currently needs application instances.",
	)
)

func init() {
	monitoring.MustRegister(svcPendingAppInstUpdate)
}

// ApplicationInstanceCache is an eventually consistent pod cache
type ApplicationInstanceCache struct {
	informer cache.SharedIndexInformer

	sync.RWMutex

	// appSvcByAppInstKey maintains application instance key to application service resource-id mapping
	appSvcByAppInstKey map[string]string

	// needResync is map of application instance key to service key. This is used to requeue service
	// events when application instance event comes. This typically happens when application instance
	//  is not available in cache when service event comes.
	needResync map[string]sets.Set

	c *Controller
}

func newApplicationInstanceCache(c *Controller, informer appsinformers.ApplicationInstanceInformer) *ApplicationInstanceCache {
	out := &ApplicationInstanceCache{
		informer:           informer.Informer(),
		appSvcByAppInstKey: make(map[string]string),
		needResync:         make(map[string]sets.Set),
		c:                  c,
	}

	return out
}

// onEvent updates the Application Instance cache
func (ac *ApplicationInstanceCache) onEvent(curr interface{}, ev model.Event) error {
	ac.Lock()
	defer ac.Unlock()

	ai, ok := curr.(*appsv1.ApplicationInstance)
	if !ok {
		tombstone, ok := curr.(cache.DeletedFinalStateUnknown)
		if !ok {
			return fmt.Errorf("couldn't get object from tombstone %+v", curr)
		}
		ai, ok = tombstone.Obj.(*appsv1.ApplicationInstance)
		if !ok {
			return fmt.Errorf("tombstone contained object that is not a application instance %#v", curr)
		}
	}

	log.Debugf("Handle event %s for application instance %s in namespace %s", ev, ai.Name, ai.Namespace)

	appSvc, ok := ai.GetObjectMeta().GetAnnotations()[model.ApplicationServiceResourceIdLabel]
	if !ok || len(appSvc) < 1 {
		log.Infof("Application instance %s doesn't have application service annotation", ai.GetName())
		return nil
	}

	key := kube.KeyFunc(ai.Name, ai.Namespace)

	switch ev {
	case model.EventAdd:
		ac.update(key, appSvc)
	case model.EventUpdate:
		if ai.DeletionTimestamp != nil {
			// delete only if this application instance was in the cache
			if _, ok := ac.appSvcByAppInstKey[key]; ok {
				ac.delete(key)
			}
		} else {
			ac.update(key, appSvc)
		}
	case model.EventDelete:
		// delete only if this application instance was in the cache
		if _, ok := ac.appSvcByAppInstKey[key]; ok {
			ac.delete(key)
		}
	}

	return nil
}

func (ac *ApplicationInstanceCache) delete(key string) {
	delete(ac.appSvcByAppInstKey, key)
}

func (ac *ApplicationInstanceCache) update(key, appSvc string) {
	ac.appSvcByAppInstKey[key] = appSvc

	if svcsToUpdate, exists := ac.needResync[key]; exists {
		delete(ac.needResync, key)
		for svc := range svcsToUpdate {
			ac.triggerServiceEvent(svc)
		}

		svcPendingAppInstUpdate.Record(float64(len(ac.needResync)))
	}
}

func (ac *ApplicationInstanceCache) triggerServiceEvent(svc string) {

	item, exists, err := ac.c.serviceInformer.GetIndexer().GetByKey(svc)
	if err != nil {
		log.Debugf("Service %v lookup failed with error %v, skipping stale service", svc, err)
		return
	}
	if !exists {
		log.Debugf("Service %v not found, skipping stale service", svc)
		return
	}
	ac.c.queue.Push(func() error {
		return ac.c.onServiceEvent(item, model.EventUpdate)
	})
}

// queueServiceEvent registers this application instance and queues service event
// when the corresponding service arrives.
func (ac *ApplicationInstanceCache) queueServiceEvent(appInst, svc string) {
	ac.Lock()
	defer ac.Unlock()
	if _, f := ac.needResync[appInst]; !f {
		ac.needResync[appInst] = sets.NewSet(svc)
	} else {
		ac.needResync[appInst].Insert(svc)
	}

	svcPendingAppInstUpdate.Record(float64(len(ac.needResync)))
}

// getApplicationService returns the application service reource-id if exists
func (ac *ApplicationInstanceCache) getApplicationService(key string) (string, bool) {
	ac.RLock()
	defer ac.RUnlock()
	appSvc, exists := ac.appSvcByAppInstKey[key]
	return appSvc, exists
}

func resolveApplicationService(c *Controller, attr *model.ServiceAttributes) {
	appInstName, ok := attr.Labels[model.ApplicationInstanceNameLabel]
	if !ok {
		return
	}

	attr.ApplicationInstance = appInstName
	appInstKey := kube.KeyFunc(appInstName, attr.Namespace)
	appSvc, exists := c.appInsts.getApplicationService(appInstKey)
	if exists {
		attr.ApplicationService = appSvc
		return
	} else {
		// TODO: need to queue the svc for application instance
		svcKey := kube.KeyFunc(attr.Name, attr.Namespace)
		log.Debugf("Service %s without application instance %s error: %v", svcKey, appInstKey)

		c.appInsts.queueServiceEvent(appInstKey, svcKey)
	}

}
