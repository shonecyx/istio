package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube"
	kubelib "istio.io/istio/pkg/kube"

	appsv1 "tess.io/ebay/api/apps/v1alpha2"
	tessclient "tess.io/ebay/client-go/tess"
)

// Prepare k8s. This can be used in multiple tests, to
// avoid duplicating creation, which can be tricky. It can be used with the fake or
// standalone apiserver.
func initTestEnvWithTessApi(t *testing.T, c kubelib.ExtendedClient, fx *FakeXdsUpdater) {

	ki := c.Kube()
	tess := c.Tess()

	cleanupTestEnvWithTessApi(tess)
	initTestEnv(t, ki, fx)
}

func cleanupTestEnvWithTessApi(ci tessclient.Interface) {
	for _, n := range []string{"nsa", "nsb"} {
		n := n

		ais, err := ci.AppsV1alpha2().ApplicationInstances(n).List(context.TODO(), metav1.ListOptions{})
		if err == nil {
			// Make sure the pods don't exist
			for _, ai := range ais.Items {
				_ = ci.AppsV1alpha2().ApplicationInstances(ai.Namespace).Delete(context.TODO(), ai.Name, metav1.DeleteOptions{})
			}
		}
	}
}

func TestApplicationInstanceCache(t *testing.T) {
	features.EnableTessCustomStats = true

	t.Run("fakeTessApiserver", func(t *testing.T) {
		t.Parallel()
		testApplicationInstanceCache(t)
	})
}

func testApplicationInstanceCache(t *testing.T) {

	fakeClient := kubelib.NewFakeClient()
	c, fx := NewFakeControllerWithOptions(FakeControllerOptions{
		Client:            fakeClient,
		Mode:              EndpointsOnly,
		WatchedNamespaces: "nsa,nsb",
	})
	defer c.Stop()

	initTestEnvWithTessApi(t, fakeClient, fx)

	ais := []*appsv1.ApplicationInstance{
		generateApplicationInstance("foo", "nsa", map[string]string{model.ApplicationServiceResourceIdLabel: "foo-app:foo-prod"}),
		generateApplicationInstance("bar", "nsa", map[string]string{model.ApplicationServiceResourceIdLabel: "bar-app:bar-prod"}),
		generateApplicationInstance("foo", "nsb", map[string]string{model.ApplicationServiceResourceIdLabel: "foo-app:foo-prod"}),
	}

	addApplicationInstances(t, c, fx, ais...)

	// Verify appliction instance cache
	wantAppSvcs := map[string]string{
		"nsa/foo": "foo-app:foo-prod",
		"nsa/bar": "bar-app:bar-prod",
		"nsb/foo": "foo-app:foo-prod",
	}

	for appInst, want := range wantAppSvcs {
		actual, exists := c.appInsts.getApplicationService(appInst)
		if !exists {
			t.Errorf("Not found: Application instance %s", appInst)
		}

		if actual != want {
			t.Errorf("Expected %s, but got %s", want, actual)
		}
	}

	// verify non-exist application instance
	appSvc, exists := c.appInsts.getApplicationService("unknown/unkonwn")
	if len(appSvc) > 0 || exists {
		t.Error("Expected not found but was found")
	}
}

func TestApplicationInstanceCacheEvents(t *testing.T) {
	features.EnableTessCustomStats = true
	t.Parallel()

	fakeClient := kubelib.NewFakeClient()
	c, _ := NewFakeControllerWithOptions(FakeControllerOptions{
		Client: fakeClient,
		Mode:   EndpointsOnly,
	})

	ns := "default"
	f := c.appInsts.onEvent

	// Application instance has no annotation "applicationservice.cms.tess.io/resource-id"
	ai1 := generateApplicationInstance("ai1", ns, map[string]string{})
	key1 := kube.KeyFunc(ai1.Name, ai1.Namespace)
	if err := f(ai1, model.EventAdd); err != nil {
		t.Error(err)
	}
	appSvc, exists := c.appInsts.getApplicationService(key1)
	if exists || len(appSvc) > 0 {
		t.Error("getApplicationService shouldn't return non-exist application service")
	}

	// Update application instance with annotation
	ai1 = generateApplicationInstance("ai1", ns, map[string]string{model.ApplicationServiceResourceIdLabel: "ai1-app:ai1-prod"})
	if err := f(ai1, model.EventUpdate); err != nil {
		t.Error(err)
	}
	appSvc, exists = c.appInsts.getApplicationService(key1)
	if !exists || appSvc != "ai1-app:ai1-prod" {
		t.Errorf("getApplicationService => got %s, application service not found or incorrect", appSvc)
	}

	// Application instance has annotation
	ai2 := generateApplicationInstance("ai2", ns, map[string]string{model.ApplicationServiceResourceIdLabel: "ai2-app:ai2-prod"})
	key2 := kube.KeyFunc(ai2.Name, ai2.Namespace)
	if err := f(ai2, model.EventAdd); err != nil {
		t.Error(err)
	}
	appSvc, exists = c.appInsts.getApplicationService(key2)
	if !exists || appSvc != "ai2-app:ai2-prod" {
		t.Errorf("getApplicationService => got %s, application service not found or incorrect", appSvc)
	}

	// Change application service resource id, this shouldn't happen in reality,
	// it's only for verifying the behavior of implementation.
	ai2 = generateApplicationInstance("ai2", ns, map[string]string{model.ApplicationServiceResourceIdLabel: "ai2-app:ai2-dev"})
	if err := f(ai2, model.EventUpdate); err != nil {
		t.Error(err)
	}
	appSvc, exists = c.appInsts.getApplicationService(key2)
	if !exists || appSvc != "ai2-app:ai2-dev" {
		t.Errorf("getApplicationService => got %s, application service not found or incorrect", appSvc)
	}

	if err := f(ai2, model.EventDelete); err != nil {
		t.Error(err)
	}
	appSvc, exists = c.appInsts.getApplicationService(key2)
	if exists || len(appSvc) > 0 {
		t.Errorf("getApplicationService => got %s, want none", appSvc)
	}

}

func generateApplicationInstance(name, namespace string, annotations map[string]string) *appsv1.ApplicationInstance {
	return &appsv1.ApplicationInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
			Namespace:   namespace,
		},
	}
}

func addApplicationInstances(t *testing.T, controller *FakeController, fx *FakeXdsUpdater, ais ...*appsv1.ApplicationInstance) {
	for _, ai := range ais {
		var current *appsv1.ApplicationInstance
		var err error
		current, _ = controller.tessClient.AppsV1alpha2().ApplicationInstances(ai.Namespace).Get(context.TODO(), ai.Name, metav1.GetOptions{})
		if current == nil {
			current, err = controller.tessClient.AppsV1alpha2().ApplicationInstances(ai.Namespace).Create(context.TODO(), ai, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("Cannot create application instance %s in namespace %s (error: %v)", ai.ObjectMeta.Name, ai.ObjectMeta.Namespace, err)
			}
		} else {
			current, err = controller.tessClient.AppsV1alpha2().ApplicationInstances(ai.Namespace).Update(context.TODO(), ai, metav1.UpdateOptions{})
			if err != nil {
				t.Fatalf("Cannot update application instance %s in namespace %s (error: %v)", ai.ObjectMeta.Name, ai.ObjectMeta.Namespace, err)
			}
		}

		_ = current
		key := kube.KeyFunc(ai.Name, ai.Namespace)
		if err := waitForApplicationInstance(controller, key); err != nil {
			t.Fatal(err)
		}
	}
}

func waitForApplicationInstance(c *FakeController, key string) error {
	return wait.Poll(5*time.Millisecond, 1*time.Second, func() (bool, error) {
		c.appInsts.RLock()
		defer c.appInsts.RUnlock()
		if _, ok := c.appInsts.appSvcByAppInstKey[key]; ok {
			return true, nil
		}
		return false, nil
	})
}
