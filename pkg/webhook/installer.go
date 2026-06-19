package webhook

import (
	"context"
	"fmt"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Installer struct {
	client    kubernetes.Interface
	namespace string
	service   string
	caBundle  []byte
	port      int32
}

func NewInstaller(client kubernetes.Interface, namespace, service string, caBundle []byte, port int32) *Installer {
	return &Installer{
		client:    client,
		namespace: namespace,
		service:   service,
		caBundle:  caBundle,
		port:      port,
	}
}

func (i *Installer) Install(ctx context.Context) error {
	failPolicy := admissionregv1.Ignore
	sideEffects := admissionregv1.SideEffectClassNone
	path := "/mutate"

	webhook := &admissionregv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubedagger-injector",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "kubedagger",
			},
		},
		Webhooks: []admissionregv1.MutatingWebhook{
			{
				Name:                    "injector.kubedagger.io",
				FailurePolicy:           &failPolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admissionregv1.WebhookClientConfig{
					Service: &admissionregv1.ServiceReference{
						Namespace: i.namespace,
						Name:      i.service,
						Path:      &path,
						Port:      &i.port,
					},
					CABundle: i.caBundle,
				},
				Rules: []admissionregv1.RuleWithOperations{
					{
						Operations: []admissionregv1.OperationType{
							admissionregv1.Create,
						},
						Rule: admissionregv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
				},
				NamespaceSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubedagger.io/inject",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"enabled"},
						},
					},
				},
			},
		},
	}

	_, err := i.client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(ctx, webhook, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create webhook config: %w", err)
	}

	return nil
}

func (i *Installer) Uninstall(ctx context.Context) error {
	err := i.client.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(ctx, "kubedagger-injector", metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("delete webhook config: %w", err)
	}
	return nil
}
