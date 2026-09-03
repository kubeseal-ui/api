package kubernetes

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	corefake "k8s.io/client-go/kubernetes/fake"
)

var sealedSecretGVR = schema.GroupVersionResource{Group: "bitnami.com", Version: "v1alpha1", Resource: "sealedsecrets"}

func TestClientListsAndGetsSealedSecrets(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "bitnami.com/v1alpha1", "kind": "SealedSecret",
		"metadata": map[string]any{"name": "db", "namespace": "apps", "annotations": map[string]any{"sealedsecrets.bitnami.com/scope": "strict"}},
		"spec":     map[string]any{"encryptedData": map[string]any{"password": "cipher"}},
	}}
	d := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sealedSecretGVR: "SealedSecretList"}, obj)
	c := NewClient(corefake.NewSimpleClientset(), d, Options{})
	got, err := c.GetSealedSecret(context.Background(), "apps", "db")
	if err != nil || got.Name != "db" || got.Scope != "strict" || !strings.Contains(got.YAML, "SealedSecret") {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	list, err := c.ListSealedSecrets(context.Background(), "apps")
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
}

func TestClientListsNamespacesSorted(t *testing.T) {
	c := NewClient(corefake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "z"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "a"}}), nil, Options{})
	got, err := c.ListNamespaces(context.Background())
	if err != nil || len(got) != 2 || got[0].Name != "a" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestClientSelectsNewestValidLabeledKeyAndSanitizesErrors(t *testing.T) {
	key, cert := validPrivateKey(t)
	old := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "controller", CreationTimestamp: metav1.NewTime(time.Unix(1, 0))}, Data: map[string][]byte{"tls.crt": cert, "tls.key": key}}
	newer := old.DeepCopy()
	newer.Name = "new"
	newer.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
	newer.Data["tls.crt"] = cert
	bad := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "controller", CreationTimestamp: metav1.NewTime(time.Unix(3, 0)), Labels: map[string]string{"active": "yes"}}, Data: map[string][]byte{"tls.crt": cert, "tls.key": []byte("private")}}
	old.Labels = map[string]string{"active": "yes"}
	newer.Labels = old.Labels
	c := NewClient(corefake.NewSimpleClientset(old, newer, bad), dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()), Options{ControllerNamespace: "controller", ActiveKeyLabel: "active=yes"})
	got, err := c.FindActiveControllerKey(context.Background())
	if err != nil || got.Name != "new" || string(got.Key) != string(key) {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if _, err := c.GetSealedSecret(context.Background(), "x", "y"); err != ErrNotFound {
		t.Fatalf("not found=%v", err)
	}
}

func validPrivateKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Keep yaml imported while fixtures are intentionally unstructured.
var _ = yaml.NewYAMLOrJSONDecoder
