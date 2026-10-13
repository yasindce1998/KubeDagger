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

package vap_backdoor

import (
	"context"
	"strings"
	"testing"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/yasindce1998/KubeDagger/internal/testutil"
)

func TestParseLabel(t *testing.T) {
	tests := []struct {
		name      string
		label     string
		wantKey   string
		wantValue string
		wantErr   bool
	}{
		{name: "empty defaults", label: "", wantKey: "kubedagger-backdoor", wantValue: "true"},
		{name: "whitespace defaults", label: "   ", wantKey: "kubedagger-backdoor", wantValue: "true"},
		{name: "valid key=value", label: "app=protected", wantKey: "app", wantValue: "protected"},
		{name: "dotted key", label: "kubedagger.io/backdoor=yes", wantKey: "kubedagger.io/backdoor", wantValue: "yes"},
		{name: "missing value", label: "key=", wantErr: true},
		{name: "missing key", label: "=value", wantErr: true},
		{name: "no equals sign", label: "keyvalue", wantErr: true},
		{name: "space in key", label: "bad key=value", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, value, err := ParseLabel(tt.label)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseLabel(%q) err = %v, wantErr %v", tt.label, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if key != tt.wantKey || value != tt.wantValue {
				t.Errorf("ParseLabel(%q) = (%q, %q), want (%q, %q)", tt.label, key, value, tt.wantKey, tt.wantValue)
			}
		})
	}
}

func TestDeployCreatesPolicyAndBinding(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
	}{
		{name: "cluster-wide binding", namespace: "all"},
		{name: "namespaced binding", namespace: "default"},
		{name: "custom namespace", namespace: "production"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := testutil.NewFakeKubeClient()
			ctx := context.Background()

			var summary strings.Builder
			if err := Deploy(ctx, client, tt.namespace, "kubedagger-backdoor=true", &summary); err != nil {
				t.Fatalf("Deploy: %v", err)
			}

			vap, err := client.AdmissionregistrationV1beta1().
				ValidatingAdmissionPolicies().
				Get(ctx, PolicyName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get ValidatingAdmissionPolicy: %v", err)
			}
			if vap.Name != PolicyName {
				t.Errorf("policy name = %q, want %q", vap.Name, PolicyName)
			}
			if len(vap.Spec.Validations) != 1 {
				t.Fatalf("validations = %d, want 1", len(vap.Spec.Validations))
			}
			expression := vap.Spec.Validations[0].Expression
			for _, want := range []string{"oldObject.metadata.labels", "kubedagger-backdoor", "'true'"} {
				if !strings.Contains(expression, want) {
					t.Errorf("expression %q missing %q", expression, want)
				}
			}

			rules := vap.Spec.MatchConstraints.ResourceRules
			if len(rules) != 3 {
				t.Fatalf("resource rules = %d, want 3 (core, apps, batch)", len(rules))
			}
			for _, rule := range rules {
				if len(rule.Operations) != 1 || rule.Operations[0] != admissionv1beta1.Delete {
					t.Errorf("rule for %v must match only DELETE, got %v", rule.Resources, rule.Operations)
				}
			}

			binding, err := client.AdmissionregistrationV1beta1().
				ValidatingAdmissionPolicyBindings().
				Get(ctx, BindingName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get ValidatingAdmissionPolicyBinding: %v", err)
			}
			if binding.Spec.PolicyName != PolicyName {
				t.Errorf("binding policyName = %q, want %q", binding.Spec.PolicyName, PolicyName)
			}
			if len(binding.Spec.ValidationActions) != 1 || binding.Spec.ValidationActions[0] != admissionv1beta1.Deny {
				t.Errorf("validationActions = %v, want [Deny]", binding.Spec.ValidationActions)
			}

			scoped := tt.namespace != "" && tt.namespace != "all"
			if scoped {
				if binding.Spec.MatchResources == nil || binding.Spec.MatchResources.NamespaceSelector == nil {
					t.Fatal("namespaced binding must set a namespaceSelector")
				}
			} else if binding.Spec.MatchResources != nil {
				t.Error("cluster-wide binding must not set matchResources")
			}

			out := summary.String()
			for _, want := range []string{PolicyName, BindingName, "Cleanup:", "kubectl delete validatingadmissionpolicy"} {
				if !strings.Contains(out, want) {
					t.Errorf("summary missing %q", want)
				}
			}
		})
	}
}

func TestDeployRejectsInvalidLabel(t *testing.T) {
	client := testutil.NewFakeKubeClient()

	if err := Deploy(context.Background(), client, "default", "noequalsign", &strings.Builder{}); err == nil {
		t.Error("Deploy with invalid label should fail")
	}
}

func TestDeployNotAvailableHint(t *testing.T) {
	client := testutil.NewFakeKubeClient()
	fakeClient, ok := client.(*kubefake.Clientset)
	if !ok {
		t.Fatalf("testutil fake client is %T, want *kubefake.Clientset", client)
	}

	noMatch := &meta.NoKindMatchError{
		GroupKind:        schema.GroupKind{Group: "admissionregistration.k8s.io", Kind: "ValidatingAdmissionPolicy"},
		SearchedVersions: []string{"v1beta1"},
	}
	fakeClient.PrependReactor("create", "validatingadmissionpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, noMatch
	})

	err := Deploy(context.Background(), fakeClient, "default", defaultLabel, &strings.Builder{})
	if err == nil {
		t.Fatal("Deploy should fail when the API is not served")
	}
	if !strings.Contains(err.Error(), "1.30") {
		t.Errorf("error should mention the Kubernetes >= 1.30 requirement, got: %v", err)
	}
}

func TestNotAvailableHint(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "not found",
			err:  apierrors.NewNotFound(schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicies"}, PolicyName),
			want: "the API is not registered on this cluster",
		},
		{
			name: "no kind match",
			err:  &meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "admissionregistration.k8s.io", Kind: "ValidatingAdmissionPolicy"}},
			want: "the API is not registered on this cluster",
		},
		{
			name: "other error",
			err:  apierrors.NewForbidden(schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicies"}, PolicyName, nil),
			want: "unexpected API error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := notAvailableHint(tt.err); got != tt.want {
				t.Errorf("notAvailableHint() = %q, want %q", got, tt.want)
			}
		})
	}
}
