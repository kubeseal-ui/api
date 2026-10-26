package kubernetes

import (
	"encoding/json"
	"fmt"
	"strings"

	"sigs.k8s.io/yaml"
)

// Annotation namespaces recording how a manifest was applied rather than what it is; stripped everywhere they are
// read or written so drift comparison, sealing normalization, and projection agree (last-applied would carry back every stripped field).
var gitopsAnnotationPrefixes = []string{
	"kubectl.kubernetes.io/",
	"argocd.argoproj.io/",
	"helm.sh/",
	"meta.helm.sh/",
	"fluxcd.io/",
	"kustomize.toolkit.fluxcd.io/",
}

// Label namespaces recording which tool owns a manifest; ownership is the delivering tool's business, not the Secret's.
var gitopsLabelPrefixes = []string{
	"argocd.argoproj.io/",
	"helm.sh/",
}

// Assigned by the API server to one live object; carrying them into a manifest records something never true of the file.
var runtimeMetadataFields = []string{
	"uid", "resourceVersion", "generation", "creationTimestamp", "managedFields", "selfLink",
}

// CleanMetadata drops what the cluster and the delivering tool recorded about an object, leaving what its author wrote.
func CleanMetadata(meta map[string]any) {
	for _, field := range runtimeMetadataFields {
		delete(meta, field)
	}
	cleanAnnotations(meta)
	cleanLabels(meta)
}

// CanonicalManifest is the document every manifest consumer reads: volatile runtime and GitOps-tracking fields stripped, so a comparison sees no false divergence.
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

// ManifestFromObject renders a live object as the manifest its file holds: the cleaning CanonicalManifest applies,
// encoded as YAML. Sharing CleanMetadata makes the projection idempotent under the comparison, so drift resolves on either side.
func ManifestFromObject(object map[string]any) (string, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return "", fmt.Errorf("marshal sealed secret: %w", err)
	}
	// JSON is a YAML subset, so the object takes the comparison's own parse — into a fresh map, keeping this off the caller's map.
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
