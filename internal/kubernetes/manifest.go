package kubernetes

import (
	"encoding/json"
	"fmt"
	"strings"

	"sigs.k8s.io/yaml"
)

// gitopsAnnotationPrefixes are the annotation namespaces that record how a manifest was applied
// rather than what it is. They are stripped everywhere a manifest is read or written — the drift
// comparison, the seal path's normalization, and the projection below — so the three agree. The
// concrete case: kubectl.kubernetes.io/last-applied-configuration holds the whole object as JSON,
// which is noise in a file and would carry back every field the normalizer strips.
var gitopsAnnotationPrefixes = []string{
	"kubectl.kubernetes.io/",
	"argocd.argoproj.io/",
	"helm.sh/",
	"meta.helm.sh/",
	"fluxcd.io/",
	"kustomize.toolkit.fluxcd.io/",
}

// gitopsLabelPrefixes are the label namespaces that record which tool owns a manifest; ownership
// is the delivering tool's business, not the Secret's.
var gitopsLabelPrefixes = []string{
	"argocd.argoproj.io/",
	"helm.sh/",
}

// runtimeMetadataFields are assigned by the API server to one live object; carrying them into a
// manifest records something that was never true of the file, and the next apply would fight them.
var runtimeMetadataFields = []string{
	"uid", "resourceVersion", "generation", "creationTimestamp", "managedFields", "selfLink",
}

// CleanMetadata drops what the cluster and the delivering tool recorded about an object, leaving
// what its author wrote. Callers that also refuse an owner reference — a claim about another
// cluster — delete it themselves, since only the seal path has to.
func CleanMetadata(meta map[string]any) {
	for _, field := range runtimeMetadataFields {
		delete(meta, field)
	}
	cleanAnnotations(meta)
	cleanLabels(meta)
}

// CanonicalManifest is the document every manifest consumer reads: a manifest with the volatile
// runtime and GitOps-tracking fields stripped, so a comparison sees the spec and the stable
// metadata without false divergences.
func CanonicalManifest(manifest string) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal([]byte(manifest), &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	delete(m, "status")
	if meta, ok := m["metadata"].(map[string]any); ok {
		CleanMetadata(meta)
	}
	if spec, ok := m["spec"].(map[string]any); ok {
		if tpl, ok := spec["template"].(map[string]any); ok {
			if tplMeta, ok := tpl["metadata"].(map[string]any); ok {
				delete(tplMeta, "creationTimestamp")
				cleanAnnotations(tplMeta)
				cleanLabels(tplMeta)
				if len(tplMeta) == 0 {
					delete(tpl, "metadata")
				}
			}
		}
	}
	return m, nil
}

// ManifestFromObject renders a live object as the manifest its file holds: the cleaning
// CanonicalManifest applies, encoded as YAML rather than echoed as the API server returned it.
//
// Sharing CleanMetadata is what makes the projection idempotent under the comparison —
// CanonicalManifest of the projection equals CanonicalManifest of the object — which is what lets
// drift be resolved without depending on which side has been through here. Serving the object
// raw instead is how a JSON blob carrying managedFields reached the YAML view and the commit.
func ManifestFromObject(object map[string]any) (string, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return "", fmt.Errorf("marshal sealed secret: %w", err)
	}
	// JSON is a YAML subset, so the object takes the comparison's own parse. That is also what
	// keeps this off the caller's map: unmarshalling into a fresh map copies it.
	doc, err := CanonicalManifest(string(raw))
	if err != nil {
		return "", fmt.Errorf("project sealed secret: %w", err)
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("encode sealed secret: %w", err)
	}
	return string(out), nil
}

func cleanAnnotations(meta map[string]any) {
	ann, ok := meta["annotations"].(map[string]any)
	if !ok {
		return
	}
	for k := range ann {
		if hasAnyPrefix(k, gitopsAnnotationPrefixes) {
			delete(ann, k)
		}
	}
	if len(ann) == 0 {
		delete(meta, "annotations")
	}
}

func cleanLabels(meta map[string]any) {
	labels, ok := meta["labels"].(map[string]any)
	if !ok {
		return
	}
	for k := range labels {
		if hasAnyPrefix(k, gitopsLabelPrefixes) {
			delete(labels, k)
		}
	}
	if len(labels) == 0 {
		delete(meta, "labels")
	}
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
