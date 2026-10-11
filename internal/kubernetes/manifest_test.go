package kubernetes

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// liveObject is what an API server answers with: the author's fields, the server's record of having
// stored it, and the delivering tool's record of having applied it.
func liveObject() map[string]any {
	return map[string]any{
		"apiVersion": "bitnami.com/v1alpha1",
		"kind":       "SealedSecret",
		"metadata": map[string]any{
			"name":              "tet",
			"namespace":         "immich",
			"uid":               "6f0c1e2a-0000-4000-8000-000000000000",
			"resourceVersion":   "48211903",
			"generation":        int64(3),
			"creationTimestamp": "2026-09-01T12:00:00Z",
			"selfLink":          "/apis/bitnami.com/v1alpha1/namespaces/immich/sealedsecrets/tet",
			"managedFields": []any{
				map[string]any{"manager": "kubeseal", "operation": "Update", "time": "2026-10-09T23:49:38Z"},
			},
			"labels": map[string]any{"app.kubernetes.io/name": "immich", "argocd.argoproj.io/instance": "immich"},
			"annotations": map[string]any{
				"sealedsecrets.bitnami.com/scope":                    "namespace-wide",
				"kubectl.kubernetes.io/last-applied-configuration":   `{"apiVersion":"bitnami.com/v1alpha1"}`,
				"argocd.argoproj.io/tracking-id":                     "immich:SealedSecret:immich/tet",
				"argocd.argoproj.io/sync-wave":                       "-1",
			},
		},
		"spec": map[string]any{
			"encryptedData": map[string]any{"password": "AgByAAAAcipher", "api_key": "AgByBBBBother"},
			"template":      map[string]any{"metadata": map[string]any{"creationTimestamp": nil}},
		},
		"status": map[string]any{"observedGeneration": int64(3)},
	}
}

func TestManifestFromObjectDropsTheClustersBookkeeping(t *testing.T) {
	out, err := ManifestFromObject(liveObject())
	if err != nil {
		t.Fatalf("err=%v", err)
	}

	// A manifest is what the file holds, so nothing the server or the delivering tool recorded
	// about having stored and applied it may survive — least of all the apply annotation, which
	// embeds the whole object.
	for _, gone := range []string{
		"managedFields", "resourceVersion", "uid:", "generation", "selfLink",
		"last-applied-configuration", "tracking-id", "sync-wave", "status", "observedGeneration",
	} {
		if strings.Contains(out, gone) {
			t.Errorf("projection kept %q:\n%s", gone, out)
		}
	}
	// …and what the Secret's author wrote is what is left.
	for _, kept := range []string{
		"kind: SealedSecret", "name: tet", "namespace: immich",
		"sealedsecrets.bitnami.com/scope: namespace-wide",
		"app.kubernetes.io/name: immich",
		"password: AgByAAAAcipher",
	} {
		if !strings.Contains(out, kept) {
			t.Errorf("projection lost %q:\n%s", kept, out)
		}
	}
	// YAML rather than the JSON it was read as: the object as the API server returned it is what
	// reached the YAML view and the commit before this.
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("projection is not YAML:\n%s", out)
	}
}

// The invariant the whole projection rests on: taking a live object through it must not move the
// document the drift comparison reads. If it did, which side of a comparison had been projected
// would decide whether a Secret looked in sync.
func TestManifestFromObjectIsIdempotentUnderTheComparison(t *testing.T) {
	raw, err := json.Marshal(liveObject())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want, err := CanonicalManifest(string(raw))
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}

	projected, err := ManifestFromObject(liveObject())
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	got, err := CanonicalManifest(projected)
	if err != nil {
		t.Fatalf("canonical of projection: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projection moved the canonical document:\n got=%#v\nwant=%#v", got, want)
	}
}

// A second pass is a no-op, which is the same property from the other side: a file the app wrote is
// already canonical, so serving it back and projecting it again cannot drift.
func TestManifestFromObjectIsStable(t *testing.T) {
	once, err := ManifestFromObject(liveObject())
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	doc, err := CanonicalManifest(once)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	twice, err := ManifestFromObject(doc)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if twice != once {
		t.Fatalf("second projection differs:\n%s\n---\n%s", once, twice)
	}
}
