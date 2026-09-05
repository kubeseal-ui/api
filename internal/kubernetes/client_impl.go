package kubernetes

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	coreclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var sealedSecretResource = schema.GroupVersionResource{Group: "bitnami.com", Version: "v1alpha1", Resource: "sealedsecrets"}

type Options struct {
	ControllerNamespace string
	ActiveKeyLabel      string
}

type KubeClient struct {
	core    coreclient.Interface
	dynamic dynamic.Interface
	options Options
}

func NewClient(core coreclient.Interface, dyn dynamic.Interface, options Options) Client {
	if options.ControllerNamespace == "" {
		options.ControllerNamespace = "cluster"
	}
	if options.ActiveKeyLabel == "" {
		options.ActiveKeyLabel = "sealedsecrets.bitnami.com/sealed-secrets-key"
	}
	return &KubeClient{core: core, dynamic: dyn, options: options}
}

// NewClientFromConfig constructs a production client from a Kubernetes REST configuration.
func NewClientFromConfig(config *rest.Config, options Options) (Client, error) {
	core, err := coreclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic kubernetes client: %w", err)
	}
	return NewClient(core, dyn, options), nil
}

func (c *KubeClient) ListNamespaces(ctx context.Context) ([]Namespace, error) {
	list, err := c.core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	out := make([]Namespace, 0, len(list.Items))
	for _, item := range list.Items {
		out = append(out, Namespace{Name: item.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *KubeClient) GetSealedSecret(ctx context.Context, namespace, name string) (SealedSecret, error) {
	if c.dynamic == nil {
		return SealedSecret{}, fmt.Errorf("sealed secret client unavailable")
	}
	obj, err := c.dynamic.Resource(sealedSecretResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return SealedSecret{}, ErrNotFound
		}
		return SealedSecret{}, fmt.Errorf("get sealed secret: %w", err)
	}
	return projectSealedSecret(obj)
}

func (c *KubeClient) ListSealedSecrets(ctx context.Context, namespace string) ([]SealedSecret, error) {
	if c.dynamic == nil {
		return nil, fmt.Errorf("sealed secret client unavailable")
	}
	list, err := c.dynamic.Resource(sealedSecretResource).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list sealed secrets: %w", err)
	}
	out := make([]SealedSecret, 0, len(list.Items))
	for i := range list.Items {
		item, err := projectSealedSecret(&list.Items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func projectSealedSecret(obj *unstructured.Unstructured) (SealedSecret, error) {
	raw, err := obj.MarshalJSON()
	if err != nil {
		return SealedSecret{}, fmt.Errorf("marshal sealed secret: %w", err)
	}
	var annotations = obj.GetAnnotations()
	scope := annotations["sealedsecrets.bitnami.com/scope"]
	return SealedSecret{Name: obj.GetName(), Namespace: obj.GetNamespace(), Scope: scope, YAML: string(raw)}, nil
}

func (c *KubeClient) FindActiveControllerKey(ctx context.Context) (ActiveKey, error) {
	label := c.options.ActiveKeyLabel
	list, err := c.core.CoreV1().Secrets(c.options.ControllerNamespace).List(ctx, metav1.ListOptions{LabelSelector: label})
	if err != nil {
		return ActiveKey{}, fmt.Errorf("list controller keys: %w", err)
	}
	valid := make([]corev1.Secret, 0, len(list.Items))
	for _, item := range list.Items {
		certBlock, _ := pem.Decode(item.Data["tls.crt"])
		keyBlock, _ := pem.Decode(item.Data["tls.key"])
		if certBlock == nil || keyBlock == nil {
			continue
		}
		cert, certErr := x509.ParseCertificate(certBlock.Bytes)
		if certErr != nil {
			continue
		}
		var privateKey any
		if parsed, keyErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); keyErr == nil {
			privateKey = parsed
		} else if parsed, keyErr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); keyErr == nil {
			privateKey = parsed
		}
		if privateKey == nil {
			continue
		}
		publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		keyRSA, ok := privateKey.(*rsa.PrivateKey)
		if !ok || keyRSA.N.Cmp(publicKey.N) != 0 || keyRSA.E != publicKey.E {
			continue
		}
		valid = append(valid, item)
	}
	if len(valid) == 0 {
		return ActiveKey{}, fmt.Errorf("no valid active controller key")
	}
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].CreationTimestamp.Equal(&valid[j].CreationTimestamp) {
			return valid[i].Name < valid[j].Name
		}
		return valid[i].CreationTimestamp.After(valid[j].CreationTimestamp.Time)
	})
	best := valid[0]
	return ActiveKey{Name: best.Name, Key: append([]byte(nil), best.Data["tls.key"]...)}, nil
}
