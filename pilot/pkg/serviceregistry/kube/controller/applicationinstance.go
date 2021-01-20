package controller

import (
	"fmt"
	"sync"

	appsv1 "tess.io/ebay/api/apps/v1alpha2"
	appsinformers "tess.io/ebay/client-go/informers/apps/v1alpha2"

	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube"
	"istio.io/pkg/log"
)

// ApplicationInstanceCache is an eventually consistent cache
type ApplicationInstanceCache struct {
	informer cache.SharedIndexInformer

	sync.RWMutex

	// appSvcByAppInstKey maintains application instance key to application service resource-id mapping
	appSvcByAppInstKey map[string]string

	c *Controller
}

func newApplicationInstanceCache(c *Controller, informer appsinformers.ApplicationInstanceInformer) *ApplicationInstanceCache {
	out := &ApplicationInstanceCache{
		informer:           informer.Informer(),
		c:                  c,
		appSvcByAppInstKey: make(map[string]string),
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

	appSvc, ok := ai.GetObjectMeta().GetAnnotations()[model.ApplicationServiceResourceIdLabel]
	if !ok {
		log.Debugf("Application instance %s doesn't have application service annotation", ai.GetName())
		return nil
	}

	if len(appSvc) > 0 {
		key := kube.KeyFunc(ai.Name, ai.Namespace)

		switch ev {
		case model.EventAdd:
			log.Debugf("Add application instance %s with application service $s", key, appSvc)
			ac.update(key, appSvc)
		case model.EventUpdate:
			if ai.DeletionTimestamp != nil {
				log.Debugf("Update application instance %s with delete timestamp", key)
				// delete only if this was in the cache
				if _, ok := ac.appSvcByAppInstKey[key]; ok {
					ac.delete(key)
				}
			} else {
				log.Debugf("Update application instance %s with application service $s", key, appSvc)
				ac.update(key, appSvc)
			}
		case model.EventDelete:
			// delete only if this was in the cache
			if _, ok := ac.appSvcByAppInstKey[key]; ok {
				ac.delete(key)
			}
		}
	}

	return nil
}

func (ac *ApplicationInstanceCache) delete(key string) {
	delete(ac.appSvcByAppInstKey, key)
}

func (ac *ApplicationInstanceCache) update(key, appSvc string) {
	ac.appSvcByAppInstKey[key] = appSvc
}

// getApplicationService returns the application service reource-id if exists
func (ac *ApplicationInstanceCache) getApplicationService(key string) (string, bool) {
	ac.RLock()
	defer ac.RUnlock()
	appSvc, exists := ac.appSvcByAppInstKey[key]
	return appSvc, exists
}
