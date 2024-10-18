//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/descriptor"
	v1 "github.com/regclient/regclient/types/oci/v1"
)

func TestOCIRegistryCollectionPipeline(t *testing.T) {
	ctx := context.Background()

	m := newMockHandler(t)

	ts := httptest.NewServer(m)
	defer ts.Close()

	parsedURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("Failed to parse test server URL: %v", err)
	}
	registry := parsedURL.Host
	m.registry = registry

	// Just for testing purposes
	rcOpts := []regclient.Opt{
		regclient.WithConfigHost([]config.Host{{
			Name:     registry,
			Hostname: registry,
			TLS:      config.TLSDisabled,
		}}...),
	}
	g := NewOCIRegistryCollector(ctx, registry, false, 0, rcOpts...)

	if err := collector.RegisterDocumentCollector(g, OCIRegistryCollector); err != nil &&
		!errors.Is(err, collector.ErrCollectorOverwrite) {
		t.Fatalf("could not register collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var collectedDocs []*processor.Document
	em := func(d *processor.Document) error {
		collectedDocs = append(collectedDocs, d)
		return nil
	}
	eh := func(err error) bool {
		if err != nil {
			t.Fatalf("Collector error handler error: %v", err)
		}
		return true
	}

	if err := collector.Collect(ctx, em, eh); err != nil {
		t.Fatalf("Collector error: %v", err)
	}

	if len(collectedDocs) != 1 {
		t.Fatalf("Expected 1 collected document, got %d", len(collectedDocs))
	}

	doc := collectedDocs[0]
	validateCollectedDocument(t, doc, m)
}

func validateCollectedDocument(t *testing.T, doc *processor.Document, m *mockHandler) {
	t.Helper()

	if doc.Type != processor.DocumentSPDX {
		t.Errorf("doc.Type = %v, want %v", doc.Type, processor.DocumentSPDX)
	}
	if doc.Format != processor.FormatJSON {
		t.Errorf("doc.Format = %v, want %v", doc.Format, processor.FormatJSON)
	}
	if doc.Encoding != "" {
		t.Errorf("doc.Encoding = %v, want %v", doc.Encoding, "")
	}
	if doc.SourceInformation.Collector != OCICollector {
		t.Errorf("doc.SourceInformation.Collector = %v, want %v", doc.SourceInformation.Collector, OCICollector)
	}
	expectedSource := fmt.Sprintf("%s/%s@%s", m.registry, m.repo, m.sbomDigest.String())
	if doc.SourceInformation.Source != expectedSource {
		t.Errorf("doc.SourceInformation.Source = %v, want %v", doc.SourceInformation.Source, expectedSource)
	}
	if doc.SourceInformation.DocumentRef != strings.ReplaceAll(m.sbomBlobDigest.String(), ":", "_") {
		t.Errorf("doc.SourceInformation.DocumentRef = %v, want %v", doc.SourceInformation.DocumentRef, strings.ReplaceAll(m.sbomBlobDigest.String(), ":", "_"))
	}
}

type mockHandler struct {
	t                *testing.T
	registry         string
	repo             string
	imageTag         string
	imageManifest    v1.Manifest
	imageBytes       []byte
	imageDigest      digest.Digest
	imageLayerBytes  []byte
	imageLayerDigest digest.Digest
	sbomTag          string
	sbomManifest     v1.Manifest
	sbomBytes        []byte
	sbomDigest       digest.Digest
	sbomBlobBytes    []byte
	sbomBlobDigest   digest.Digest
}

func newMockHandler(t *testing.T) *mockHandler {
	imageLayerBytes := []byte("mock image layer content")
	imageLayerDigest := digest.FromBytes(imageLayerBytes)

	sbomBlobBytes := []byte("mock SBOM content")
	sbomBlobDigest := digest.FromBytes(sbomBlobBytes)

	mockRepo := "ubuntu"
	imageTag := "latest"
	sbomTag := "latest.sbom"

	imageManifest := v1.Manifest{
		Versioned: v1.ManifestSchemaVersion,
		Config: descriptor.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    digest.FromString("mock image config"),
			Size:      1,
		},
		Layers: []descriptor.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:    imageLayerDigest,
				Size:      int64(len(imageLayerBytes)),
			},
		},
	}
	imageBytes, err := json.Marshal(imageManifest)
	if err != nil {
		t.Fatalf("Failed to marshal image manifest: %v", err)
	}
	imageDigest := digest.FromBytes(imageBytes)

	sbomManifest := v1.Manifest{
		Versioned: v1.ManifestSchemaVersion,
		Config: descriptor.Descriptor{
			MediaType: "application/vnd.example.sbom.config.v1+json",
			Digest:    digest.FromString("mock sbom config"),
			Size:      1,
		},
		Layers: []descriptor.Descriptor{
			{
				MediaType: "application/vnd.example.sbom.layer.v1+json",
				Digest:    sbomBlobDigest,
				Size:      int64(len(sbomBlobBytes)),
			},
		},
		Annotations: map[string]string{
			"org.opencontainers.image.ref.name": sbomTag,
		},
		Subject: &descriptor.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    imageDigest,
			Size:      int64(len(imageBytes)),
		},
	}
	sbomBytes, err := json.Marshal(sbomManifest)
	if err != nil {
		t.Fatalf("Failed to marshal sbom manifest: %v", err)
	}
	sbomDigest := digest.FromBytes(sbomBytes)

	return &mockHandler{
		t:                t,
		registry:         "", // Will be set in test
		repo:             mockRepo,
		imageTag:         imageTag,
		imageManifest:    imageManifest,
		imageBytes:       imageBytes,
		imageDigest:      imageDigest,
		imageLayerBytes:  imageLayerBytes,
		imageLayerDigest: imageLayerDigest,
		sbomTag:          sbomTag,
		sbomManifest:     sbomManifest,
		sbomBytes:        sbomBytes,
		sbomDigest:       sbomDigest,
		sbomBlobBytes:    sbomBlobBytes,
		sbomBlobDigest:   sbomBlobDigest,
	}
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v2/_catalog":
		m.handleCatalog(w)
	case regexp.MustCompile(`^/v2/(.*)/tags/list$`).MatchString(r.URL.Path):
		m.handleTagsList(w, r)
	case regexp.MustCompile(`^/v2/(.*)/manifests/(.*)$`).MatchString(r.URL.Path):
		m.handleManifests(w, r)
	case regexp.MustCompile(`^/v2/(.*)/blobs/(.*)$`).MatchString(r.URL.Path):
		m.handleBlobs(w, r)
	case regexp.MustCompile(`^/v2/(.*)/referrers/(.*)$`).MatchString(r.URL.Path):
		m.handleReferrers(w, r)
	default:
		m.write404(w)
	}
}

func (m *mockHandler) handleCatalog(w http.ResponseWriter) {
	respBody := []byte(fmt.Sprintf(`{"repositories":["%s"]}`, m.repo))
	m.writeResponse(w, http.StatusOK, "application/json", respBody)
}

func (m *mockHandler) handleTagsList(w http.ResponseWriter, r *http.Request) {
	matches := regexp.MustCompile(`^/v2/(.*)/tags/list$`).FindStringSubmatch(r.URL.Path)
	repoName := matches[1]
	listTagBody := []byte(fmt.Sprintf(`{"name":"%s","tags":["%s","%s"]}`, repoName, m.imageTag, m.sbomTag))
	m.writeResponse(w, http.StatusOK, "application/json", listTagBody)
}

func (m *mockHandler) handleManifests(w http.ResponseWriter, r *http.Request) {
	matches := regexp.MustCompile(`^/v2/(.*)/manifests/(.*)$`).FindStringSubmatch(r.URL.Path)
	tagOrDigest := matches[2]

	var manifestBytes []byte
	var manifestDigest digest.Digest

	switch tagOrDigest {
	case m.imageTag, m.imageDigest.String():
		manifestBytes = m.imageBytes
		manifestDigest = m.imageDigest
	case m.sbomTag, m.sbomDigest.String():
		manifestBytes = m.sbomBytes
		manifestDigest = m.sbomDigest
	default:
		m.write404(w)
		return
	}

	w.Header().Set("Docker-Content-Digest", manifestDigest.String())
	m.writeResponse(w, http.StatusOK, "application/vnd.oci.image.manifest.v1+json", manifestBytes)
}

func (m *mockHandler) handleBlobs(w http.ResponseWriter, r *http.Request) {
	matches := regexp.MustCompile(`^/v2/(.*)/blobs/(.*)$`).FindStringSubmatch(r.URL.Path)
	reqBlobDigest := digest.Digest(matches[2])

	var blobBytes []byte
	var blobDigest digest.Digest

	switch reqBlobDigest {
	case m.imageLayerDigest:
		blobBytes = m.imageLayerBytes
		blobDigest = m.imageLayerDigest
	case m.sbomBlobDigest:
		blobBytes = m.sbomBlobBytes
		blobDigest = m.sbomBlobDigest
	default:
		m.write404(w)
		return
	}

	w.Header().Set("Docker-Content-Digest", blobDigest.String())
	m.writeResponse(w, http.StatusOK, "application/octet-stream", blobBytes)
}

func (m *mockHandler) handleReferrers(w http.ResponseWriter, r *http.Request) {
	matches := regexp.MustCompile(`^/v2/(.*)/referrers/(.*)$`).FindStringSubmatch(r.URL.Path)
	digest := matches[2]

	if digest != m.imageDigest.String() {
		m.write404(w)
		return
	}

	referrerIndex := v1.Index{
		Versioned: v1.ManifestSchemaVersion,
		MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: []descriptor.Descriptor{
			{
				MediaType:    "application/vnd.oci.image.manifest.v1+json",
				Digest:       m.sbomDigest,
				Size:         int64(len(m.sbomBytes)),
				ArtifactType: SpdxJson,
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": "sbom",
				},
			},
		},
	}

	referrerBytes, err := json.Marshal(referrerIndex)
	if err != nil {
		m.t.Fatalf("Failed to marshal referrer index: %v", err)
	}

	m.writeResponse(w, http.StatusOK, "application/vnd.oci.image.index.v1+json", referrerBytes)
}

func (m *mockHandler) writeResponse(w http.ResponseWriter, status int, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(status)
	if _, err := io.Copy(w, bytes.NewReader(body)); err != nil {
		m.t.Fatalf("Failed to write response: %v", err)
	}
}

func (m *mockHandler) write404(w http.ResponseWriter) {
	errBody := []byte(`{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry","detail":"unstructured"}]}`)
	m.writeResponse(w, http.StatusNotFound, "application/json", errBody)
}
