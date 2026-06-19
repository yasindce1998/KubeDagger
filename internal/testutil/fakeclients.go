package testutil

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// NewFakeKubeClient creates a fake Kubernetes clientset pre-seeded with objects.
func NewFakeKubeClient(objects ...runtime.Object) kubernetes.Interface {
	return kubefake.NewSimpleClientset(objects...)
}

// NewFakeDynamicClient creates a fake dynamic client with a base scheme and pre-seeded objects.
func NewFakeDynamicClient(objects ...*unstructured.Unstructured) *fake.FakeDynamicClient {
	scheme := runtime.NewScheme()

	runtimeObjects := make([]runtime.Object, len(objects))
	for i, obj := range objects {
		runtimeObjects[i] = obj
	}

	return fake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			{Group: "networking.istio.io", Version: "v1alpha3", Resource: "envoyfilters"}:    "EnvoyFilterList",
			{Group: "networking.istio.io", Version: "v1alpha3", Resource: "virtualservices"}: "VirtualServiceList",
			{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}:  "GitRepositoryList",
		},
		runtimeObjects...,
	)
}

// NewUnstructured creates an unstructured object with the given GVK, namespace, and name.
func NewUnstructured(group, version, kind, namespace, name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   group,
		Version: version,
		Kind:    kind,
	})
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return obj
}
