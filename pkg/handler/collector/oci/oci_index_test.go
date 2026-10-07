//
// Copyright 2026 The GUAC Authors.
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
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	mockregistry "github.com/guacsec/guac/internal/testing/mockRegistry"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	v1 "github.com/regclient/regclient/types/oci/v1"
	"github.com/regclient/regclient/types/platform"
)

const (
	slsaProvenanceV02 = `{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "pkg:oci/my-app",
      "digest": {
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "https://github.com/docker/buildx"
    }
  }
}`
	slsaProvenanceV1 = `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "pkg:oci/my-app",
      "digest": {
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://mobyproject.org/buildkit@v1"
    }
  }
}`
)

type buildxIndexFixture struct {
	gzipLayers                bool
	layerMediaType            string
	omitAttestationAnnotation bool
	indexArtifactType         string
	unknownPlatformImageOnly  bool
}

type buildxIndexRegistry struct {
	registry           *mockregistry.MockRegistry
	host               string
	imageRef           string
	attestationDigest  digest.Digest
	imageLayerBytes    []byte
	provenanceV02Bytes []byte
	provenanceV1Bytes  []byte
}

func TestOCICollectorSLSAProvenanceFromImageIndex(t *testing.T) {
	fx := newBuildxIndexRegistry(t, buildxIndexFixture{})
	defer fx.registry.Close()

	docs := collectOCIDocs(t, fx.host, fx.imageRef)
	assertSLSAProvenanceDocs(t, docs, fx)
}

func TestOCICollectorSLSAProvenanceGzipInTotoLayers(t *testing.T) {
	fx := newBuildxIndexRegistry(t, buildxIndexFixture{
		gzipLayers:     true,
		layerMediaType: InTotoJson + "+gzip",
	})
	defer fx.registry.Close()

	docs := collectOCIDocs(t, fx.host, fx.imageRef)
	assertSLSAProvenanceDocs(t, docs, fx)
}

func TestOCICollectorSLSAProvenanceUnknownPlatformWithoutAnnotation(t *testing.T) {
	// Harbor and some proxies drop vnd.docker.reference.type while leaving the
	// buildx unknown/unknown attestation manifest in the index.
	fx := newBuildxIndexRegistry(t, buildxIndexFixture{
		omitAttestationAnnotation: true,
	})
	defer fx.registry.Close()

	docs := collectOCIDocs(t, fx.host, fx.imageRef)
	assertSLSAProvenanceDocs(t, docs, fx)
}

func TestOCICollectorSLSAProvenanceWhenHarborHEADHidesIndex(t *testing.T) {
	fx := newBuildxIndexRegistry(t, buildxIndexFixture{})
	defer fx.registry.Close()

	host, imageRef, closeProxy := harborHEADProxy(t, fx, "application/vnd.oci.image.manifest.v1+json")
	defer closeProxy()
	fx.host = host
	fx.imageRef = imageRef

	docs := collectOCIDocs(t, host, imageRef)
	assertSLSAProvenanceDocs(t, docs, fx)
}

func TestOCICollectorSLSAProvenanceHarborHEADGzipWithoutAnnotation(t *testing.T) {
	// Closest mock of the reported Harbor + docker buildx --provenance mode=max
	// ingest: gzip in-toto layers, no attestation-manifest annotation, and a
	// HEAD Content-Type rewrite that hides the image index.
	fx := newBuildxIndexRegistry(t, buildxIndexFixture{
		gzipLayers:                true,
		layerMediaType:            InTotoJson + "+gzip",
		omitAttestationAnnotation: true,
	})
	defer fx.registry.Close()

	host, imageRef, closeProxy := harborHEADProxy(t, fx, "application/vnd.docker.distribution.manifest.v2+json")
	defer closeProxy()
	fx.host = host
	fx.imageRef = imageRef

	docs := collectOCIDocs(t, host, imageRef)
	assertSLSAProvenanceDocs(t, docs, fx)
}

func TestOCICollectorSLSAProvenanceGzipPayloadPlainInTotoMediaType(t *testing.T) {
	// docker buildx --provenance mode=max often gzips the in-toto payload while
	// still advertising application/vnd.in-toto+json without a +gzip suffix.
	fx := newBuildxIndexRegistry(t, buildxIndexFixture{
		gzipLayers:     true,
		layerMediaType: InTotoJson,
	})
	defer fx.registry.Close()

	docs := collectOCIDocs(t, fx.host, fx.imageRef)
	assertSLSAProvenanceDocs(t, docs, fx)
}

func TestOCICollectorSkipsUnknownPlatformImageLayers(t *testing.T) {
	fx := newBuildxIndexRegistry(t, buildxIndexFixture{
		omitAttestationAnnotation: true,
		unknownPlatformImageOnly:  true,
	})
	defer fx.registry.Close()

	imageLayerDigest := digest.FromBytes(fx.imageLayerBytes).String()
	host, closeTracker, blobGets := trackingRegistry(t, fx.registry.URL())
	defer closeTracker()
	fx.host = host
	fx.imageRef = fmt.Sprintf("%s/project/my-app:1.0", host)

	docs := collectOCIDocs(t, fx.host, fx.imageRef)
	if len(docs) != 0 {
		t.Fatalf("collected %d documents from unknown/unknown image layers, want 0", len(docs))
	}
	for _, path := range blobGets() {
		if strings.Contains(path, imageLayerDigest) {
			t.Fatalf("downloaded unknown/unknown image layer %s; skipUnknownLayers should classify before BlobGet", imageLayerDigest)
		}
	}
}

func TestIsIndexEmbeddedArtifact(t *testing.T) {
	tests := []struct {
		name string
		desc descriptor.Descriptor
		want bool
	}{
		{
			name: "docker buildx attestation-manifest annotation",
			desc: descriptor.Descriptor{
				Annotations: map[string]string{
					dockerReferenceTypeAnnotation: dockerAttestationManifest,
				},
			},
			want: true,
		},
		{
			name: "docker buildx index descriptor with unknown/unknown platform and no ArtifactType",
			desc: descriptor.Descriptor{
				Platform: &platform.Platform{
					Architecture: "unknown",
					OS:           "unknown",
				},
				Annotations: map[string]string{
					dockerReferenceTypeAnnotation: dockerAttestationManifest,
				},
			},
			want: true,
		},
		{
			name: "unknown/unknown platform without annotation is still inspected",
			desc: descriptor.Descriptor{
				Platform: &platform.Platform{
					Architecture: "unknown",
					OS:           "unknown",
				},
			},
			want: true,
		},
		{
			name: "well-known in-toto artifact type without annotation",
			desc: descriptor.Descriptor{
				ArtifactType: InTotoJson,
			},
			want: true,
		},
		{
			name: "gzip in-toto artifact type",
			desc: descriptor.Descriptor{
				ArtifactType: InTotoJson + "+gzip",
			},
			want: true,
		},
		{
			name: "well-known SPDX artifact type without annotation",
			desc: descriptor.Descriptor{
				ArtifactType: SpdxJson,
			},
			want: true,
		},
		{
			name: "linux/amd64 platform image is not an artifact",
			desc: descriptor.Descriptor{
				Platform: &platform.Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isIndexEmbeddedArtifact(tt.desc); got != tt.want {
				t.Errorf("isIndexEmbeddedArtifact() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDocumentTypeAndFormat(t *testing.T) {
	tests := []struct {
		name           string
		mediaType      string
		wantDocType    processor.DocumentType
		wantFormatType processor.FormatType
	}{
		{
			name:           "in-toto layer media type",
			mediaType:      InTotoJson,
			wantDocType:    processor.DocumentITE6SLSA,
			wantFormatType: processor.FormatJSON,
		},
		{
			name:           "gzip in-toto layer media type",
			mediaType:      InTotoJson + "+gzip",
			wantDocType:    processor.DocumentITE6SLSA,
			wantFormatType: processor.FormatJSON,
		},
		{
			name:           "in-toto media type with compression parameter",
			mediaType:      InTotoJson + "; compression=gzip",
			wantDocType:    processor.DocumentITE6SLSA,
			wantFormatType: processor.FormatJSON,
		},
		{
			name:           "spdx artifact type",
			mediaType:      SpdxJson,
			wantDocType:    processor.DocumentSPDX,
			wantFormatType: processor.FormatJSON,
		},
		{
			name:           "empty media type",
			mediaType:      "",
			wantDocType:    processor.DocumentUnknown,
			wantFormatType: processor.FormatUnknown,
		},
		{
			name:           "fallback tag artifactType unknown",
			mediaType:      "unknown",
			wantDocType:    processor.DocumentUnknown,
			wantFormatType: processor.FormatUnknown,
		},
		{
			name:           "unknown media type",
			mediaType:      "application/vnd.oci.image.layer.v1.tar+gzip",
			wantDocType:    processor.DocumentUnknown,
			wantFormatType: processor.FormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotFormat := documentTypeAndFormat(tt.mediaType)
			if gotType != tt.wantDocType {
				t.Errorf("documentTypeAndFormat() type = %v, want %v", gotType, tt.wantDocType)
			}
			if gotFormat != tt.wantFormatType {
				t.Errorf("documentTypeAndFormat() format = %v, want %v", gotFormat, tt.wantFormatType)
			}
		})
	}
}

func TestMaybeGunzip(t *testing.T) {
	plain := []byte(`{"hello":"world"}`)
	got, err := maybeGunzip(plain)
	if err != nil {
		t.Fatalf("maybeGunzip(plain) error = %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("maybeGunzip(plain) = %q, want original bytes", got)
	}

	compressed := gzipBytes(t, plain)
	got, err = maybeGunzip(compressed)
	if err != nil {
		t.Fatalf("maybeGunzip(gzip) error = %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("maybeGunzip(gzip) = %q, want %q", got, plain)
	}
}

func TestMaybeIndexFromRaw(t *testing.T) {
	// Omit mediaType so a rewritten Content-Type does not fail verifyMT.
	raw := []byte(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"platform":{"architecture":"amd64","os":"linux"}}]}`)

	wrongHeader := http.Header{}
	wrongHeader.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	mislabeled, err := manifest.New(manifest.WithHeader(wrongHeader), manifest.WithRaw(raw))
	if err != nil {
		t.Fatalf("manifest.New mislabeled index: %v", err)
	}
	if mislabeled.IsList() {
		t.Fatal("mislabeled index unexpectedly reported IsList before maybeIndexFromRaw")
	}
	fixed := maybeIndexFromRaw(mislabeled)
	if !fixed.IsList() {
		t.Fatal("maybeIndexFromRaw did not recover an image index from a mislabeled Content-Type")
	}

	imageRaw := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":3}]}`)
	imageHeader := http.Header{}
	imageHeader.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	imageManifest, err := manifest.New(manifest.WithHeader(imageHeader), manifest.WithRaw(imageRaw))
	if err != nil {
		t.Fatalf("manifest.New image: %v", err)
	}
	got := maybeIndexFromRaw(imageManifest)
	if got.IsList() {
		t.Fatal("maybeIndexFromRaw treated a non-index body as an image index")
	}
}

func TestCanonicalArtifactMediaType(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{InTotoJson, InTotoJson},
		{InTotoJson + "+gzip", InTotoJson},
		{InTotoJson + "; compression=gzip", InTotoJson},
		{SpdxJson + "+gzip", SpdxJson},
	}
	for _, tt := range tests {
		if got := canonicalArtifactMediaType(tt.in); got != tt.want {
			t.Errorf("canonicalArtifactMediaType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func newBuildxIndexRegistry(t *testing.T, opt buildxIndexFixture) *buildxIndexRegistry {
	t.Helper()

	imageLayerBytes := []byte("mock image layer content")
	imageLayerDigest := digest.FromBytes(imageLayerBytes)
	provenanceV02Bytes := []byte(slsaProvenanceV02)
	provenanceV1Bytes := []byte(slsaProvenanceV1)
	emptyConfigBytes := []byte("{}")
	emptyConfigDigest := digest.FromBytes(emptyConfigBytes)

	layerMediaType := opt.layerMediaType
	if layerMediaType == "" {
		layerMediaType = InTotoJson
	}

	v02LayerBytes := provenanceV02Bytes
	v1LayerBytes := provenanceV1Bytes
	if opt.gzipLayers {
		v02LayerBytes = gzipBytes(t, provenanceV02Bytes)
		v1LayerBytes = gzipBytes(t, provenanceV1Bytes)
	}
	v02LayerDigest := digest.FromBytes(v02LayerBytes)
	v1LayerDigest := digest.FromBytes(v1LayerBytes)

	imageManifest := v1.Manifest{
		Versioned: v1.ManifestSchemaVersion,
		MediaType: "application/vnd.oci.image.manifest.v1+json",
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

	var attestationLayers []descriptor.Descriptor
	if opt.unknownPlatformImageOnly {
		attestationLayers = []descriptor.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:    imageLayerDigest,
				Size:      int64(len(imageLayerBytes)),
			},
		}
	} else {
		attestationLayers = []descriptor.Descriptor{
			{
				MediaType: layerMediaType,
				Digest:    v02LayerDigest,
				Size:      int64(len(v02LayerBytes)),
				Annotations: map[string]string{
					"in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2",
				},
			},
			{
				MediaType: layerMediaType,
				Digest:    v1LayerDigest,
				Size:      int64(len(v1LayerBytes)),
				Annotations: map[string]string{
					"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1",
				},
			},
		}
	}

	attestationManifest := v1.Manifest{
		Versioned: v1.ManifestSchemaVersion,
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Config: descriptor.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    emptyConfigDigest,
			Size:      int64(len(emptyConfigBytes)),
		},
		Layers: attestationLayers,
	}
	attestationBytes, err := json.Marshal(attestationManifest)
	if err != nil {
		t.Fatalf("Failed to marshal attestation manifest: %v", err)
	}
	attestationDigest := digest.FromBytes(attestationBytes)

	attestationDesc := descriptor.Descriptor{
		MediaType:    "application/vnd.oci.image.manifest.v1+json",
		Digest:       attestationDigest,
		Size:         int64(len(attestationBytes)),
		ArtifactType: opt.indexArtifactType,
		Platform: &platform.Platform{
			Architecture: "unknown",
			OS:           "unknown",
		},
	}
	if !opt.omitAttestationAnnotation {
		attestationDesc.Annotations = map[string]string{
			"vnd.docker.reference.type":   "attestation-manifest",
			"vnd.docker.reference.digest": imageDigest.String(),
		}
	}

	index := v1.Index{
		Versioned: v1.IndexSchemaVersion,
		MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: []descriptor.Descriptor{
			{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Digest:    imageDigest,
				Size:      int64(len(imageBytes)),
				Platform: &platform.Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
			},
			attestationDesc,
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("Failed to marshal image index: %v", err)
	}
	indexDigest := digest.FromBytes(indexBytes)

	blobs := map[string][]byte{
		imageLayerDigest.String():  imageLayerBytes,
		emptyConfigDigest.String(): emptyConfigBytes,
	}
	if !opt.unknownPlatformImageOnly {
		blobs[v02LayerDigest.String()] = v02LayerBytes
		blobs[v1LayerDigest.String()] = v1LayerBytes
	}

	content := &mockregistry.RegistryContent{
		Repositories: map[string]*mockregistry.RepositoryContent{
			"project/my-app": {
				Tags: map[string]string{
					"1.0": indexDigest.String(),
				},
				Manifests: map[string]mockregistry.ManifestContent{
					indexDigest.String(): {
						Content:   indexBytes,
						MediaType: "application/vnd.oci.image.index.v1+json",
						Digest:    indexDigest,
					},
					imageDigest.String(): {
						Content:   imageBytes,
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    imageDigest,
					},
					attestationDigest.String(): {
						Content:   attestationBytes,
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    attestationDigest,
					},
				},
				Blobs: blobs,
			},
		},
	}

	registry := mockregistry.NewMockRegistry(content)
	parsedURL, err := url.Parse(registry.URL())
	if err != nil {
		registry.Close()
		t.Fatalf("Failed to parse mock registry URL: %v", err)
	}
	host := parsedURL.Host
	return &buildxIndexRegistry{
		registry:           registry,
		host:               host,
		imageRef:           fmt.Sprintf("%s/project/my-app:1.0", host),
		attestationDigest:  attestationDigest,
		imageLayerBytes:    imageLayerBytes,
		provenanceV02Bytes: provenanceV02Bytes,
		provenanceV1Bytes:  provenanceV1Bytes,
	}
}

func harborHEADProxy(t *testing.T, fx *buildxIndexRegistry, headContentType string) (host, imageRef string, closeFn func()) {
	t.Helper()
	return harborContentTypeProxy(t, fx, headContentType, false)
}

func harborContentTypeProxy(t *testing.T, fx *buildxIndexRegistry, contentType string, rewriteGET bool) (host, imageRef string, closeFn func()) {
	t.Helper()
	backend, err := url.Parse(fx.registry.URL())
	if err != nil {
		t.Fatalf("Failed to parse mock registry URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backend)
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Request == nil || !strings.Contains(resp.Request.URL.Path, "/manifests/") {
			return nil
		}
		if resp.Request.Method == http.MethodHead || (rewriteGET && resp.Request.Method == http.MethodGet) {
			// Harbor has been observed rewriting index Content-Type to a
			// single image manifest type while the body is still an index.
			resp.Header.Set("Content-Type", contentType)
		}
		return nil
	}
	harbor := httptest.NewServer(proxy)
	parsedURL, err := url.Parse(harbor.URL)
	if err != nil {
		harbor.Close()
		t.Fatalf("Failed to parse Harbor-like proxy URL: %v", err)
	}
	host = parsedURL.Host
	imageRef = fmt.Sprintf("%s/project/my-app:1.0", host)
	return host, imageRef, harbor.Close
}

func trackingRegistry(t *testing.T, registryURL string) (host string, closeFn func(), blobGets func() []string) {
	t.Helper()
	backend, err := url.Parse(registryURL)
	if err != nil {
		t.Fatalf("Failed to parse mock registry URL: %v", err)
	}
	var mu sync.Mutex
	var gets []string
	proxy := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(backend)
			req.Out.Host = req.In.Host
			if req.Out.Method == http.MethodGet && strings.Contains(req.Out.URL.Path, "/blobs/") {
				mu.Lock()
				gets = append(gets, req.Out.URL.Path)
				mu.Unlock()
			}
		},
	}
	srv := httptest.NewServer(proxy)
	parsedURL, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("Failed to parse tracking proxy URL: %v", err)
	}
	return parsedURL.Host, srv.Close, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(gets))
		copy(out, gets)
		return out
	}
}

func collectOCIDocs(t *testing.T, registryHost, imageRef string) []*processor.Document {
	t.Helper()
	ctx := context.Background()

	rcOpts := getRegClientOptions()
	rcOpts = append(rcOpts,
		regclient.WithConfigHost([]config.Host{{
			Name:     registryHost,
			Hostname: registryHost,
			TLS:      config.TLSDisabled,
		}}...),
	)

	g := NewOCICollector(ctx, imageCollectSource(t, []string{imageRef}), false, 0, rcOpts...)

	collector.DeregisterDocumentCollector(OCICollector)
	t.Cleanup(func() {
		collector.DeregisterDocumentCollector(OCICollector)
	})
	if err := collector.RegisterDocumentCollector(g, OCICollector); err != nil &&
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
			t.Errorf("Collector error handler error: %v", err)
		}
		return true
	}

	if err := collector.Collect(ctx, em, eh); err != nil {
		t.Fatalf("Collector error: %v", err)
	}
	return collectedDocs
}

func assertSLSAProvenanceDocs(t *testing.T, collectedDocs []*processor.Document, fx *buildxIndexRegistry) {
	t.Helper()
	if len(collectedDocs) != 2 {
		t.Fatalf("completed ingesting %d documents, want 2 SLSA provenance documents from the image index", len(collectedDocs))
	}

	expectedSource := fmt.Sprintf("%s/project/my-app@%s", fx.host, fx.attestationDigest)
	gotBlobs := map[string]bool{}
	for _, doc := range collectedDocs {
		if doc.Type != processor.DocumentITE6SLSA {
			t.Errorf("doc.Type = %v, want %v", doc.Type, processor.DocumentITE6SLSA)
		}
		if doc.Format != processor.FormatJSON {
			t.Errorf("doc.Format = %v, want %v", doc.Format, processor.FormatJSON)
		}
		if doc.SourceInformation.Collector != OCICollector {
			t.Errorf("doc.SourceInformation.Collector = %v, want %v", doc.SourceInformation.Collector, OCICollector)
		}
		if doc.SourceInformation.Source != expectedSource {
			t.Errorf("doc.SourceInformation.Source = %v, want %v", doc.SourceInformation.Source, expectedSource)
		}
		if string(doc.Blob) == string(fx.imageLayerBytes) {
			t.Errorf("collected image layer blob; unknown/unknown attestation descriptor should not walk the platform image layers")
		}
		gotBlobs[string(doc.Blob)] = true
	}
	if !gotBlobs[string(fx.provenanceV02Bytes)] {
		t.Errorf("missing SLSA provenance v0.2 statement")
	}
	if !gotBlobs[string(fx.provenanceV1Bytes)] {
		t.Errorf("missing SLSA provenance v1 statement")
	}
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func imageCollectSource(t *testing.T, ociValues []string) datasource.CollectSource {
	t.Helper()
	values := make([]datasource.Source, 0, len(ociValues))
	for _, v := range ociValues {
		values = append(values, datasource.Source{Value: v})
	}

	ds, err := inmemsource.NewInmemDataSources(&datasource.DataSources{
		OciDataSources: values,
	})
	if err != nil {
		t.Fatalf("unable to create in-memory data source: %v", err)
	}
	return ds
}
