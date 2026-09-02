package kubernetes

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ts(t time.Time) metav1.Time { return metav1.NewTime(t) }

func keySecret(name string, created time.Time, withKey bool) Secret {
	data := map[string][]byte{"tls.crt": []byte("cert")}
	if withKey {
		data["tls.key"] = []byte("key-material")
	}
	return Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: ts(created)},
		Data:       data,
	}
}

// TestFakeClientListNamespaces verifies sorted, deterministic output.
func TestFakeClientListNamespaces(t *testing.T) {
	f := NewFake(
		[]Namespace{{Name: "db"}, {Name: "cluster"}, {Name: "apps"}},
		nil, nil,
	)
	got, err := f.ListNamespaces(context.Background())
	if err != nil {
		t.Fatalf("ListNamespaces: %v", err)
	}
	want := []string{"apps", "cluster", "db"}
	if len(got) != len(want) {
		t.Fatalf("got %d namespaces, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i] {
			t.Errorf("namespaces[%d] = %q, want %q", i, got[i].Name, want[i])
		}
	}
}

// TestFakeClientGetSealedSecret verifies exact lookup and ErrNotFound.
func TestFakeClientGetSealedSecret(t *testing.T) {
	f := NewFake(nil, []SealedSecret{
		{Name: "db-cred", Namespace: "db", Scope: "strict"},
	}, nil)

	got, err := f.GetSealedSecret(context.Background(), "db", "db-cred")
	if err != nil {
		t.Fatalf("GetSealedSecret: %v", err)
	}
	if got.Name != "db-cred" || got.Namespace != "db" {
		t.Errorf("unexpected secret: %+v", got)
	}

	if _, err := f.GetSealedSecret(context.Background(), "db", "missing"); err != ErrNotFound {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

// TestFakeClientListSealedSecrets verifies namespace filtering.
func TestFakeClientListSealedSecrets(t *testing.T) {
	f := NewFake(nil, []SealedSecret{
		{Name: "a", Namespace: "db"},
		{Name: "b", Namespace: "tools"},
		{Name: "c", Namespace: "db"},
	}, nil)

	got, err := f.ListSealedSecrets(context.Background(), "db")
	if err != nil {
		t.Fatalf("ListSealedSecrets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d secrets, want 2", len(got))
	}
	if got[0].Name != "a" || got[1].Name != "c" {
		t.Errorf("unexpected order/content: %+v", got)
	}
}
