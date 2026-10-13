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

// Command detect runs KubeDagger cloud-native security product detection
// against a cluster reachable via kubeconfig.
//
// It invokes the same cloudevasion.DetectSystems entry point used by the
// agent's cloud_evasion module (action=detect) and prints the same report,
// so the tool's real detection signatures can be exercised against a lab
// cluster (see scripts/lab/lab.sh and docs/LAB.md) without requiring the
// full C2 server/operator/agent chain.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yasindce1998/KubeDagger/pkg/cloudevasion"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	kubeconfigPath := flag.String("kubeconfig", "", "path to kubeconfig (defaults to $KUBECONFIG, then ~/.kube/config)")
	kubeContext := flag.String("context", "", "kubeconfig context to use (defaults to the current context)")
	flag.Parse()

	config, err := loadRestConfig(*kubeconfigPath, *kubeContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load kubeconfig: %v\n", err)
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create kube client: %v\n", err)
		os.Exit(1)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create dynamic client: %v\n", err)
		os.Exit(1)
	}

	systems, err := cloudevasion.DetectSystems(context.Background(), kubeClient, dynClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "detect systems: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(cloudevasion.FormatSystems(systems))
}

// loadRestConfig builds a rest config from the given kubeconfig path (falling
// back to $KUBECONFIG and ~/.kube/config) with an optional context override.
func loadRestConfig(path, contextName string) (*rest.Config, error) {
	if path == "" {
		if env := os.Getenv("KUBECONFIG"); env != "" {
			path = env
		} else if home, homeErr := os.UserHomeDir(); homeErr == nil {
			path = filepath.Join(home, ".kube", "config")
		}
	}

	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}

	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	return clientcmd.
		NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).
		ClientConfig()
}
