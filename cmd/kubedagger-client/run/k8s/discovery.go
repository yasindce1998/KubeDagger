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

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type ClusterReport struct {
	Nodes      []NodeInfo      `json:"nodes"`
	Pods       []PodInfo       `json:"pods"`
	Services   []ServiceInfo   `json:"services"`
	Namespaces []string        `json:"namespaces"`
	Targets    []AttackTarget  `json:"targets"`
}

type NodeInfo struct {
	Name       string `json:"name"`
	IP         string `json:"ip"`
	OS         string `json:"os"`
	Kernel     string `json:"kernel"`
	Kubelet    string `json:"kubelet"`
	Conditions string `json:"conditions"`
}

type PodInfo struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	NodeName   string `json:"node_name"`
	PodIP      string `json:"pod_ip"`
	Image      string `json:"image"`
	Privileged bool   `json:"privileged"`
	HostPID    bool   `json:"host_pid"`
	HostNet    bool   `json:"host_network"`
}

type ServiceInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	ClusterIP string `json:"cluster_ip"`
	Ports     string `json:"ports"`
}

type AttackTarget struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// Discover enumerates cluster resources and identifies attack targets.
func Discover(namespace string, output string) error {
	client, err := getClient()
	if err != nil {
		return fmt.Errorf("k8s client init failed: %w", err)
	}

	ctx := context.Background()
	report := &ClusterReport{}

	namespaces, err := listNamespaces(ctx, client, namespace)
	if err != nil {
		return err
	}
	report.Namespaces = namespaces

	for _, ns := range namespaces {
		if err := discoverPods(ctx, client, ns, report); err != nil {
			logrus.Warnf("failed to list pods in %s: %v", ns, err)
		}
		if err := discoverServices(ctx, client, ns, report); err != nil {
			logrus.Warnf("failed to list services in %s: %v", ns, err)
		}
	}

	if err := discoverNodes(ctx, client, report); err != nil {
		logrus.Warnf("failed to list nodes: %v", err)
	}

	identifyTargets(report)

	data, _ := json.MarshalIndent(report, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func getClient() (*kubernetes.Clientset, error) {
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

func listNamespaces(ctx context.Context, client *kubernetes.Clientset, filter string) ([]string, error) {
	if filter != "" && filter != "all" {
		return []string{filter}, nil
	}

	nsList, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var names []string
	for _, ns := range nsList.Items {
		names = append(names, ns.Name)
	}
	return names, nil
}

func discoverPods(ctx context.Context, client *kubernetes.Clientset, namespace string, report *ClusterReport) error {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, pod := range pods.Items {
		info := PodInfo{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			NodeName:  pod.Spec.NodeName,
			PodIP:     pod.Status.PodIP,
			HostPID:   pod.Spec.HostPID,
			HostNet:   pod.Spec.HostNetwork,
		}
		if len(pod.Spec.Containers) > 0 {
			info.Image = pod.Spec.Containers[0].Image
			sc := pod.Spec.Containers[0].SecurityContext
			if sc != nil && sc.Privileged != nil && *sc.Privileged {
				info.Privileged = true
			}
		}
		report.Pods = append(report.Pods, info)
	}
	return nil
}

func discoverServices(ctx context.Context, client *kubernetes.Clientset, namespace string, report *ClusterReport) error {
	svcs, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, svc := range svcs.Items {
		ports := ""
		for i, p := range svc.Spec.Ports {
			if i > 0 {
				ports += ","
			}
			ports += fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		}
		report.Services = append(report.Services, ServiceInfo{
			Name:      svc.Name,
			Namespace: svc.Namespace,
			Type:      string(svc.Spec.Type),
			ClusterIP: svc.Spec.ClusterIP,
			Ports:     ports,
		})
	}
	return nil
}

func discoverNodes(ctx context.Context, client *kubernetes.Clientset, report *ClusterReport) error {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, node := range nodes.Items {
		conditions := ""
		for _, c := range node.Status.Conditions {
			if c.Status == "True" {
				conditions += string(c.Type) + " "
			}
		}

		internalIP := ""
		for _, addr := range node.Status.Addresses {
			if addr.Type == "InternalIP" {
				internalIP = addr.Address
				break
			}
		}

		report.Nodes = append(report.Nodes, NodeInfo{
			Name:       node.Name,
			IP:         internalIP,
			OS:         node.Status.NodeInfo.OSImage,
			Kernel:     node.Status.NodeInfo.KernelVersion,
			Kubelet:    node.Status.NodeInfo.KubeletVersion,
			Conditions: conditions,
		})
	}
	return nil
}

func identifyTargets(report *ClusterReport) {
	for _, pod := range report.Pods {
		if pod.Privileged {
			report.Targets = append(report.Targets, AttackTarget{
				Name:   pod.Namespace + "/" + pod.Name,
				Type:   "privileged_pod",
				Reason: "container runs as privileged — host escape possible",
			})
		}
		if pod.HostPID {
			report.Targets = append(report.Targets, AttackTarget{
				Name:   pod.Namespace + "/" + pod.Name,
				Type:   "host_pid",
				Reason: "shares host PID namespace — process visibility/injection",
			})
		}
		if pod.HostNet {
			report.Targets = append(report.Targets, AttackTarget{
				Name:   pod.Namespace + "/" + pod.Name,
				Type:   "host_network",
				Reason: "shares host network — can sniff node traffic",
			})
		}
	}
}
