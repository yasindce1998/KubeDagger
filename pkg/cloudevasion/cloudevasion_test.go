/*
Copyright © 2023 MOHAMMED YASIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cloudevasion

import (
	"context"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"

	"github.com/yasindce1998/KubeDagger/internal/testutil"
)

// cloudevasionDynGVRs lists every GVR the cloudevasion package reads through
// the dynamic client. The fake dynamic client panics on List for GVRs without
// a registered list kind, so tests driving DetectSystems (or evasion
// techniques that touch the dynamic client) must register all of them.
var cloudevasionDynGVRs = []schema.GroupVersionResource{
	{Group: "security.istio.io", Version: "v1beta1", Resource: "peerauthentications"},
	{Group: "security.istio.io", Version: "v1beta1", Resource: "authorizationpolicies"},
	{Group: "policy.linkerd.io", Version: "v1beta1", Resource: "serverauthorizations"},
	{Group: "networking.istio.io", Version: "v1alpha3", Resource: "envoyfilters"},
	{Group: "spiffeid.spiffe.io", Version: "v1beta1", Resource: "spiffeids"},
	{Group: "spire.spiffe.io", Version: "v1alpha1", Resource: "clusterspiffeids"},
	{Group: "policy.sigstore.dev", Version: "v1beta1", Resource: "clusterimagepolicies"},
	{Group: "cert-manager.io", Version: "v1", Resource: "issuers"},
	{Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers"},
	{Group: "cert-manager.io", Version: "v1", Resource: "certificates"},
	{Group: "velero.io", Version: "v1", Resource: "backups"},
	{Group: "velero.io", Version: "v1", Resource: "schedules"},
	{Group: "velero.io", Version: "v1", Resource: "backupstoragelocations"},
	{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
	{Group: "cilium.io", Version: "v2", Resource: "ciliumendpoints"},
	{Group: "cilium.io", Version: "v1alpha1", Resource: "tracingpolicies"},
	{Group: "kyverno.io", Version: "v1", Resource: "clusterpolicies"},
	{Group: "kyverno.io", Version: "v1", Resource: "policies"},
	{Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets"},
	{Group: "external-secrets.io", Version: "v1beta1", Resource: "secretstores"},
	{Group: "external-secrets.io", Version: "v1beta1", Resource: "clustersecretstores"},
	{Group: "falco.org", Version: "v1", Resource: "falcorules"},
	{Group: "serving.knative.dev", Version: "v1", Resource: "services"},
	{Group: "serving.knative.dev", Version: "v1", Resource: "revisions"},
	{Group: "security.kubearmor.com", Version: "v1", Resource: "kubearmorpolicies"},
	{Group: "apiextensions.crossplane.io", Version: "v1", Resource: "compositions"},
	{Group: "apiextensions.crossplane.io", Version: "v1", Resource: "compositeresourcedefinitions"},
	{Group: "pkg.crossplane.io", Version: "v1", Resource: "providers"},
	{Group: "argoproj.io", Version: "v1alpha1", Resource: "workflowtemplates"},
	{Group: "argoproj.io", Version: "v1alpha1", Resource: "clusterworkflowtemplates"},
	{Group: "argoproj.io", Version: "v1alpha1", Resource: "workflows"},
}

// newCloudevasionDynamicFake returns a fake dynamic client with list kinds
// registered for every cloudevasion GVR and no seeded objects, so all
// dynamic-backed detections report not-detected. testutil.NewFakeDynamicClient
// only registers the istio/flux list kinds, which is not enough for
// DetectSystems (the dynamic fake panics on unregistered List calls).
func newCloudevasionDynamicFake() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	listKinds := make(map[schema.GroupVersionResource]string, len(cloudevasionDynGVRs))
	for _, gvr := range cloudevasionDynGVRs {
		listKinds[gvr] = gvr.Resource + "List"
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)
}

// standinPod builds a minimal stand-in pod matching a detection signature.
func standinPod(name, namespace string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "standin", Image: "busybox:1.36"}},
		},
	}
}

func TestDetectSystems(t *testing.T) {
	objects := []runtime.Object{
		standinPod("falco-sensor-standin", "falco", map[string]string{"app": "falco"}),
		standinPod("kyverno-standin", "kyverno", map[string]string{"app.kubernetes.io/name": "kyverno"}),
		standinPod("cilium-agent-standin", "cilium", map[string]string{"k8s-app": "cilium"}),
		standinPod("tetragon-standin", "kube-system", map[string]string{"app.kubernetes.io/name": "tetragon"}),
		standinPod("harbor-core-standin", "harbor", map[string]string{"app": "harbor"}),
		standinPod("velero-standin", "velero", map[string]string{"component": "velero"}),
		standinPod("kubescape-standin", "kubescape", map[string]string{"app.kubernetes.io/name": "kubescape"}),
		standinPod("trivy-operator-standin", "trivy-system", map[string]string{"app.kubernetes.io/name": "trivy-operator"}),
	}
	client := testutil.NewFakeKubeClient(objects...)
	dynClient := newCloudevasionDynamicFake()

	systems, err := DetectSystems(context.Background(), client, dynClient)
	if err != nil {
		t.Fatalf("DetectSystems: %v", err)
	}

	byName := make(map[string]DetectionSystem, len(systems))
	for _, s := range systems {
		byName[s.Name] = s
	}

	expected := map[string]string{
		"cnative-sensor":   "falco",
		"cnative-policy":   "kyverno",
		"cnative-net":      "cilium",
		"cnative-probe":    "kube-system",
		"cnative-registry": "harbor",
		"cnative-backup":   "velero",
		"cnative-audit":    "kubescape",
		"cnative-scanner":  "trivy-system",
	}
	for name, ns := range expected {
		s, ok := byName[name]
		if !ok {
			t.Errorf("expected %s in DetectSystems results", name)
			continue
		}
		if !s.Detected {
			t.Errorf("%s: Detected = false, want true", name)
		}
		if s.Namespace != ns {
			t.Errorf("%s: Namespace = %q, want %q", name, s.Namespace, ns)
		}
	}
}

func TestDetectSystemsEmptyCluster(t *testing.T) {
	client := testutil.NewFakeKubeClient()
	dynClient := newCloudevasionDynamicFake()

	systems, err := DetectSystems(context.Background(), client, dynClient)
	if err != nil {
		t.Fatalf("DetectSystems: %v", err)
	}
	for _, s := range systems {
		if s.Detected {
			t.Errorf("%s: Detected = true on empty cluster, want false", s.Name)
		}
	}
}

func TestDetectStandinSignatures(t *testing.T) {
	tests := []struct {
		name          string
		detect        func(context.Context, kubernetes.Interface) []DetectionSystem
		pod           *corev1.Pod
		wantName      string
		wantNamespace string
	}{
		{
			name:          "cnative-sensor",
			detect:        detectCnativeSensor,
			pod:           standinPod("falco-sensor-standin", "falco", map[string]string{"app": "falco"}),
			wantName:      "cnative-sensor",
			wantNamespace: "falco",
		},
		{
			name:          "cnative-policy",
			detect:        detectCnativePolicy,
			pod:           standinPod("kyverno-standin", "kyverno", map[string]string{"app.kubernetes.io/name": "kyverno"}),
			wantName:      "cnative-policy",
			wantNamespace: "kyverno",
		},
		{
			name:          "cnative-net",
			detect:        detectCnativeNet,
			pod:           standinPod("cilium-agent-standin", "cilium", map[string]string{"k8s-app": "cilium"}),
			wantName:      "cnative-net",
			wantNamespace: "cilium",
		},
		{
			name:          "cnative-probe",
			detect:        detectCnativeProbe,
			pod:           standinPod("tetragon-standin", "kube-system", map[string]string{"app.kubernetes.io/name": "tetragon"}),
			wantName:      "cnative-probe",
			wantNamespace: "kube-system",
		},
		{
			name:          "cnative-registry",
			detect:        detectCnativeRegistry,
			pod:           standinPod("harbor-core-standin", "harbor", map[string]string{"app": "harbor"}),
			wantName:      "cnative-registry",
			wantNamespace: "harbor",
		},
		{
			name:          "cnative-backup",
			detect:        detectCnativeBackup,
			pod:           standinPod("velero-standin", "velero", map[string]string{"component": "velero"}),
			wantName:      "cnative-backup",
			wantNamespace: "velero",
		},
		{
			name:          "cnative-audit",
			detect:        detectCnativeAudit,
			pod:           standinPod("kubescape-standin", "kubescape", map[string]string{"app.kubernetes.io/name": "kubescape"}),
			wantName:      "cnative-audit",
			wantNamespace: "kubescape",
		},
		{
			name:          "cnative-scanner",
			detect:        detectCnativeScanner,
			pod:           standinPod("trivy-operator-standin", "trivy-system", map[string]string{"app.kubernetes.io/name": "trivy-operator"}),
			wantName:      "cnative-scanner",
			wantNamespace: "trivy-system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_present", func(t *testing.T) {
			client := testutil.NewFakeKubeClient(tt.pod)
			systems := tt.detect(context.Background(), client)
			if len(systems) != 1 {
				t.Fatalf("expected exactly 1 detection, got %d", len(systems))
			}
			s := systems[0]
			if !s.Detected {
				t.Errorf("Detected = false, want true")
			}
			if s.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", s.Name, tt.wantName)
			}
			if s.Namespace != tt.wantNamespace {
				t.Errorf("Namespace = %q, want %q", s.Namespace, tt.wantNamespace)
			}
		})

		t.Run(tt.name+"_absent", func(t *testing.T) {
			client := testutil.NewFakeKubeClient()
			systems := tt.detect(context.Background(), client)
			if len(systems) != 0 {
				t.Errorf("expected no detections on empty cluster, got %d: %+v", len(systems), systems)
			}
		})
	}
}

func TestEvadeCnativeSensorSymlink(t *testing.T) {
	result, err := EvadeCnativeSensor(context.Background(), testutil.NewFakeKubeClient(), newCloudevasionDynamicFake(), "symlink")
	if err != nil {
		t.Fatalf("EvadeCnativeSensor symlink: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Technique != "symlink_traversal" {
		t.Errorf("Technique = %q, want %q", result.Technique, "symlink_traversal")
	}
	if result.Output == "" {
		t.Error("expected non-empty output")
	}
	if !strings.Contains(result.Output, "cnative-sensor Symlink Evasion") {
		t.Errorf("output does not mention symlink evasion: %q", result.Output)
	}
}

func TestEvadeCnativeSensorFlood(t *testing.T) {
	result, err := EvadeCnativeSensor(context.Background(), testutil.NewFakeKubeClient(), newCloudevasionDynamicFake(), "flood")
	if err != nil {
		t.Fatalf("EvadeCnativeSensor flood: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Technique != "flood" {
		t.Errorf("Technique = %q, want %q", result.Technique, "flood")
	}
	if result.Output == "" {
		t.Error("expected non-empty output")
	}
}

func TestEvadeCnativeAuditScanTiming(t *testing.T) {
	cronJob := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubescape-scheduled-scan",
			Namespace: "kubescape",
		},
		Spec: batchv1.CronJobSpec{
			Schedule: "0 */6 * * *",
		},
	}
	client := testutil.NewFakeKubeClient(cronJob)

	result, err := EvadeCnativeAudit(context.Background(), client, newCloudevasionDynamicFake(), "scan_timing")
	if err != nil {
		t.Fatalf("EvadeCnativeAudit scan_timing: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Success {
		t.Errorf("Success = false, want true (kubescape CronJob is seeded)")
	}
	if !strings.Contains(result.Output, "kubescape-scheduled-scan") {
		t.Errorf("output does not mention the seeded scan job: %q", result.Output)
	}
}

func TestFormatSystems(t *testing.T) {
	if got := FormatSystems(nil); got != "No detection systems found in cluster" {
		t.Errorf("FormatSystems(nil) = %q, want empty-cluster message", got)
	}

	out := FormatSystems([]DetectionSystem{
		{Name: "cnative-sensor", Detected: true, Namespace: "falco", Details: "1 pods running"},
	})
	if !strings.Contains(out, "[ACTIVE] cnative-sensor") {
		t.Errorf("output missing ACTIVE marker: %q", out)
	}

	out = FormatSystems([]DetectionSystem{
		{Name: "cnative-probe", Detected: false, Namespace: "", Details: ""},
	})
	if !strings.Contains(out, "[not detected] cnative-probe") {
		t.Errorf("output missing not-detected marker: %q", out)
	}
}
