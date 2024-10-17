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

	"math/rand"

	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/docker/schema2"
	"github.com/regclient/regclient/types/mediatype"
)

func TestRegistryCollectionPipeline(t *testing.T) {
	ctx := context.Background()

	m := newMockHandler(t)

	ts := httptest.NewServer(m)
	defer ts.Close()

	parsedURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("Failed to parse test server URL: %v", err)
	}
	registry := parsedURL.Host

	// Just for testing purposes
	rcOpts := getRegClientOptions()
	rcOpts = append(rcOpts, regclient.WithConfigHost([]config.Host{{
		Name:     registry,
		Hostname: registry,
		TLS:      config.TLSDisabled,
	}}...))
	g := NewOCIRegistryCollector(ctx, registry, false, 0, rcOpts...)

	if err := collector.RegisterDocumentCollector(g, OCIRegistryCollector); err != nil &&
		!errors.Is(err, collector.ErrCollectorOverwrite) {
		t.Fatalf("could not register collector: %v", err)
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
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
		t.Fatalf("Collector error handler error: %v", err)
	}
	if len(collectedDocs) != 1 {
		t.Fatalf("g.RetrieveArtifacts() = %v, want %v", len(collectedDocs), 1)
	}
	doc := collectedDocs[0]
	if doc.Type != "UNKNOWN" {
		t.Errorf("doc.Type = %v, want %v", doc.Type, "UNKNOWN")
	}
	if doc.Format != "UNKNOWN" {
		t.Errorf("doc.Format = %v, want %v", doc.Format, "UNKNOWN")
	}
	if doc.Encoding != "" {
		t.Errorf("doc.Encoding = %v, want %v", doc.Encoding, "")
	}
	if doc.SourceInformation.Collector != OCICollector {
		t.Errorf("doc.SourceInformation.Collector = %v, want %v", doc.SourceInformation.Collector, OCICollector)
	}
	expectedSource := fmt.Sprintf("%s/ubuntu:%s.sbom", registry, strings.ReplaceAll(m.sbomDigest.String(), ":", "-"))
	if doc.SourceInformation.Source != expectedSource {
		t.Errorf("doc.SourceInformation.Source = %v, want %v", doc.SourceInformation.Source, expectedSource)
	}
	if doc.SourceInformation.DocumentRef != strings.ReplaceAll(m.blobDigest.String(), ":", "_") {
		t.Errorf("doc.SourceInformation.DocumentRef = %v, want %v", doc.SourceInformation.DocumentRef, strings.ReplaceAll(m.blobDigest.String(), ":", "_"))
	}
}

type mockHandler struct {
	t            *testing.T
	repo         string
	sbomManifest schema2.Manifest
	sbomBytes    []byte
	sbomDigest   digest.Digest
	sbomLen      int
	blobBytes    []byte
	blobDigest   digest.Digest
	blobLen      int
}

func newMockHandler(t *testing.T) *mockHandler {
	// create a random blob
	seed := time.Now().UTC().Unix()
	blobSize := 1024
	blobDigest, blobBytes := NewRandomBlob(blobSize, seed)

	mockRepo := "ubuntu"
	sbomManifest := schema2.Manifest{
		Config: descriptor.Descriptor{
			MediaType: mediatype.OCI1Manifest,
			Digest:    digest.FromString("mock config"),
			Size:      1,
		},
		Layers: []descriptor.Descriptor{
			{
				MediaType:    mediatype.OCI1LayerGzip,
				Digest:       blobDigest,
				ArtifactType: "application/vnd.example.sbom",
				Size:         int64(blobSize),
				Annotations:  map[string]string{},
			},
		},
		Annotations: map[string]string{
			"extraAnnot": "org.example.sbom.format",
		},
	}
	sbomBytes, err := json.Marshal(sbomManifest)
	if err != nil {
		t.Fatalf("Failed to marshal sbom: %v", err)
	}
	sbomDigest := digest.FromBytes(sbomBytes)
	sbomLen := len(sbomBytes)

	return &mockHandler{
		t:            t,
		repo:         mockRepo,
		sbomManifest: sbomManifest,
		sbomBytes:    sbomBytes,
		sbomDigest:   sbomDigest,
		sbomLen:      sbomLen,
		blobBytes:    blobBytes,
		blobDigest:   blobDigest,
		blobLen:      blobSize,
	}

}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Inspired by https://github.com/regclient/regclient/blob/e8054262030074b96c15671e0e0d86d79233e7c7/internal/reqresp/reqresp.go#L96
	if r.URL.Path == "/v2/_catalog" {
		w.WriteHeader(http.StatusOK)
		respBody := []byte(fmt.Sprintf(`{"repositories":["%s"]}`, strings.Join([]string{m.repo}, `","`)))
		written, err := io.Copy(w, bytes.NewReader(respBody))
		if err != nil {
			m.t.Fatalf("Failed to write response: %v", err)
		}
		if written == 0 {
			m.t.Fatalf("Failed to write response")
		}
	} else if matches := regexp.MustCompile(`^/v2/(.*)/tags/list$`).FindStringSubmatch(r.URL.Path); len(matches) > 1 {
		sbomTag := fmt.Sprintf("%s-%s.sbom", m.sbomDigest.Algorithm(), m.sbomDigest.Encoded())
		repoName := matches[1]
		listTagBody := []byte(fmt.Sprintf("{\"name\":\"%s\",\"tags\":[\"%s\"]}",
			strings.TrimLeft(repoName, "/"),
			strings.Join([]string{sbomTag}, "\",\"")))
		w.WriteHeader(http.StatusOK)
		written, err := io.Copy(w, bytes.NewReader(listTagBody))
		if err != nil {
			m.t.Fatalf("Failed to write response: %v", err)
		}
		if written == 0 {
			m.t.Fatalf("Failed to write response")
		}
	} else if matches := regexp.MustCompile(`^/v2/(.*)/manifests/(.*)$`).FindStringSubmatch(r.URL.Path); len(matches) > 1 {
		tagName := matches[2]

		// only match if ends in sbom
		if !strings.HasSuffix(tagName, ".sbom") {
			m.write404(w)
			return
		}

		w.Header().Set("Content-Type", mediatype.OCI1Manifest)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", m.sbomLen))
		w.Header().Set("Docker-Content-Digest", m.sbomDigest.String())
		w.WriteHeader(http.StatusOK)
		written, err := io.Copy(w, bytes.NewReader(m.sbomBytes))
		if err != nil {
			m.t.Fatalf("Failed to write response: %v", err)
		}
		if written == 0 {
			m.t.Fatalf("Failed to write response")
		}
	} else if matches := regexp.MustCompile(`^/v2/(.*)/blobs/(.*)$`).FindStringSubmatch(r.URL.Path); len(matches) > 1 {
		reqBlobDigest := digest.Digest(matches[2])

		// make sure were only responding to the correct blob
		if m.blobDigest != reqBlobDigest {
			m.write404(w)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(m.blobBytes)))
		w.Header().Set("Docker-Content-Digest", m.blobDigest.String())
		w.WriteHeader(http.StatusOK)
		written, err := io.Copy(w, bytes.NewReader(m.blobBytes))
		if err != nil {
			m.t.Fatalf("Failed to write response: %v", err)
		}
		if written == 0 {
			m.t.Fatalf("Failed to write response")
		}
	} else {
		m.write404(w)
	}
}

// function to write a 404
func (m *mockHandler) write404(w http.ResponseWriter) {
	// https://github.com/opencontainers/distribution-spec/blob/main/spec.md#error-codes
	w.WriteHeader(http.StatusNotFound)
	written, err := io.Copy(w, bytes.NewReader([]byte(`{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry","detail":"unstructured"}]}`)))
	if err != nil {
		m.t.Fatalf("Failed to write response: %v", err)
	}
	if written == 0 {
		m.t.Fatalf("Failed to write response")
	}
}

// copied from: https://github.com/regclient/regclient/blob/e8054262030074b96c15671e0e0d86d79233e7c7/internal/reqresp/reqresp.go#L167
// changed int64 to uint64
// NewRandomBlob outputs a reproducible random blob (based on the seed) for testing
func NewRandomBlob(size int, seed int64) (digest.Digest, []byte) {
	//#nosec G404 regresp is only used for testing
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, size)
	if n, err := r.Read(b); err != nil {
		panic(err)
	} else if n != size {
		panic("unable to read enough bytes")
	}
	return digest.Canonical.FromBytes(b), b
}
