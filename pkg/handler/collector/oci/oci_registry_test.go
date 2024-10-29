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
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
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
	v1 "github.com/regclient/regclient/types/oci/v1"
)

func TestOCIRegistryCollectionPipeline(t *testing.T) {
	ctx := context.Background()

	// Create mock registry content
	imageLayerBytes := []byte("mock image layer content")
	imageLayerDigest := digest.FromBytes(imageLayerBytes)

	sbomBlobBytes := []byte("mock SBOM content")
	sbomBlobDigest := digest.FromBytes(sbomBlobBytes)

	// Create image manifest
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

	// Create SBOM manifest
	sbomManifest := v1.Manifest{
		Versioned: v1.ManifestSchemaVersion,
		Config: descriptor.Descriptor{
			MediaType: "application/vnd.example.sbom.config.v1+json",
			Digest:    digest.FromString("mock sbom config"),
			Size:      1,
		},
		ArtifactType: SpdxJson,
		Layers: []descriptor.Descriptor{
			{
				MediaType: "application/vnd.example.sbom.layer.v1+json",
				Digest:    sbomBlobDigest,
				Size:      int64(len(sbomBlobBytes)),
			},
		},
		Annotations: map[string]string{
			"org.opencontainers.image.ref.name": "latest.sbom",
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

	// Initialize mock registry content
	content := &mockregistry.RegistryContent{
		Repositories: map[string]*mockregistry.RepositoryContent{
			"ubuntu": {
				Tags: map[string]string{
					"latest":      imageDigest.String(),
					"latest.sbom": sbomDigest.String(),
				},
				Manifests: map[string]mockregistry.ManifestContent{
					imageDigest.String(): {
						Content:   imageBytes,
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    imageDigest,
						Referrers: []descriptor.Descriptor{
							{
								MediaType:    "application/vnd.oci.image.manifest.v1+json",
								Digest:       sbomDigest,
								Size:         int64(len(sbomBytes)),
								ArtifactType: SpdxJson,
								Annotations: map[string]string{
									"org.opencontainers.image.ref.name": "sbom",
								},
							},
						},
					},
					sbomDigest.String(): {
						Content:   sbomBytes,
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    sbomDigest,
						ArtifactType: SpdxJson,
					},
				},
				Blobs: map[string][]byte{
					imageLayerDigest.String(): imageLayerBytes,
					sbomBlobDigest.String():   sbomBlobBytes,
				},
			},
		},
	}

	// Create mock registry
	registry := mockregistry.NewMockRegistry(content)
	defer registry.Close()

	// Extract host from registry URL
	parsedURL, err := url.Parse(registry.URL())
	if err != nil {
		t.Fatalf("Failed to parse mock registry URL: %v", err)
	}
	registryHost := parsedURL.Host

	// Create collect data source
	ds := toRegistryDataSource(t, []string{registryHost})

	// Configure registry client options
	rcOpts := getRegClientOptions()
	rcOpts = append(rcOpts,
		regclient.WithConfigHost([]config.Host{{
			Name:     registryHost,
			Hostname: registryHost,
			TLS:      config.TLSDisabled,
		}}...),
	)

	// Create and register collector
	g := NewOCIRegistryCollector(ctx, ds, false, 0, rcOpts...)

	if err := collector.RegisterDocumentCollector(g, OCIRegistryCollector); err != nil &&
		!errors.Is(err, collector.ErrCollectorOverwrite) {
		t.Fatalf("could not register collector: %v", err)
	}
	defer func() {
		if err := collector.DeregisterDocumentCollector(OCIRegistryCollector); err != nil {
			t.Fatalf("could not deregister collector: %v", err)
		}
	}()

	// Run collection with timeout
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

	// Validate results
	if len(collectedDocs) != 1 {
		t.Fatalf("Expected 1 collected document, got %d", len(collectedDocs))
	}

	doc := collectedDocs[0]

	// Validate document properties
	if doc.Type != processor.DocumentSPDX {
		t.Errorf("doc.Type = %v, want %v", doc.Type, processor.DocumentSPDX)
	}
	if doc.Format != processor.FormatJSON {
		t.Errorf("doc.Format = %v, want %v", doc.Format, processor.FormatJSON)
	}
	if doc.Encoding != "" {
		t.Errorf("doc.Encoding = %v, want empty string", doc.Encoding)
	}
	if doc.SourceInformation.Collector != OCICollector {
		t.Errorf("doc.SourceInformation.Collector = %v, want %v", doc.SourceInformation.Collector, OCICollector)
	}

	expectedSource := fmt.Sprintf("%s/ubuntu@%s", registryHost, sbomDigest)
	if doc.SourceInformation.Source != expectedSource {
		t.Errorf("doc.SourceInformation.Source = %v, want %v", doc.SourceInformation.Source, expectedSource)
	}

	expectedDocRef := strings.ReplaceAll(sbomBlobDigest.String(), ":", "_")
	if doc.SourceInformation.DocumentRef != expectedDocRef {
		t.Errorf("doc.SourceInformation.DocumentRef = %v, want %v", doc.SourceInformation.DocumentRef, expectedDocRef)
	}
}

func toRegistryDataSource(t *testing.T, ociRegistryValues []string) datasource.CollectSource {
	values := []datasource.Source{}
	for _, v := range ociRegistryValues {
		values = append(values, datasource.Source{Value: v})
	}

	ds, err := inmemsource.NewInmemDataSources(&datasource.DataSources{
		OciRegistryDataSources: values,
	})
	if err != nil {
		panic(err)
	}
	return ds
}
