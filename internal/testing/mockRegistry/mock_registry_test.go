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

package mockregistry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/descriptor"
	v1 "github.com/regclient/regclient/types/oci/v1"
)

func TestMockRegistry_APIVersion(t *testing.T) {
	registry := NewMockRegistry(&RegistryContent{})
	defer registry.Close()

	// Test GET /v2/
	resp, err := http.Get(registry.URL() + "/v2/")
	if err != nil {
		t.Fatalf("Failed to get API version: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if v := resp.Header.Get("Docker-Distribution-API-Version"); v != "registry/2.0" {
		t.Errorf("Expected API version registry/2.0, got %s", v)
	}
}

func TestMockRegistry_Catalog(t *testing.T) {
	content := &RegistryContent{
		Repositories: map[string]*RepositoryContent{
			"repo1": {},
			"repo2": {},
		},
	}
	registry := NewMockRegistry(content)
	defer registry.Close()

	resp, err := http.Get(registry.URL() + "/v2/_catalog")
	if err != nil {
		t.Fatalf("Failed to get catalog: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var catalog struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(catalog.Repositories) != 2 {
		t.Errorf("Expected 2 repositories, got %d", len(catalog.Repositories))
	}
}

func TestMockRegistry_Tags(t *testing.T) {
	content := &RegistryContent{
		Repositories: map[string]*RepositoryContent{
			"repo1": {
				Tags: map[string]string{
					"latest": "sha256:digest1",
					"v1.0":   "sha256:digest2",
				},
			},
		},
	}
	registry := NewMockRegistry(content)
	defer registry.Close()

	tests := []struct {
		name         string
		path         string
		expectedCode int
		expectedTags []string
	}{
		{
			name:         "existing repository",
			path:         "/v2/repo1/tags/list",
			expectedCode: http.StatusOK,
			expectedTags: []string{"latest", "v1.0"},
		},
		{
			name:         "non-existent repository",
			path:         "/v2/missing/tags/list",
			expectedCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Get(registry.URL() + tt.path)
			if err != nil {
				t.Fatalf("Failed to get tags: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, resp.StatusCode)
			}

			if tt.expectedTags != nil {
				var tagList struct {
					Name string   `json:"name"`
					Tags []string `json:"tags"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&tagList); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}

				if len(tagList.Tags) != len(tt.expectedTags) {
					t.Errorf("Expected %d tags, got %d", len(tt.expectedTags), len(tagList.Tags))
				}
			}
		})
	}
}

func TestMockRegistry_Manifests(t *testing.T) {
	// Create a test manifest
	manifest := v1.Manifest{
		Versioned: v1.ManifestSchemaVersion,
		Config: descriptor.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    digest.FromString("config"),
			Size:      1,
		},
	}
	manifestBytes, _ := json.Marshal(manifest)
	manifestDigest := digest.FromBytes(manifestBytes)

	content := &RegistryContent{
		Repositories: map[string]*RepositoryContent{
			"repo1": {
				Tags: map[string]string{
					"latest": manifestDigest.String(),
				},
				Manifests: map[string]ManifestContent{
					manifestDigest.String(): {
						Content:   manifestBytes,
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    manifestDigest,
					},
				},
			},
		},
	}
	registry := NewMockRegistry(content)
	defer registry.Close()

	tests := []struct {
		name         string
		method       string
		path         string
		body         []byte
		expectedCode int
	}{
		{
			name:         "get manifest by tag",
			method:       "GET",
			path:         "/v2/repo1/manifests/latest",
			expectedCode: http.StatusOK,
		},
		{
			name:         "get manifest by digest",
			method:       "GET",
			path:         fmt.Sprintf("/v2/repo1/manifests/%s", manifestDigest),
			expectedCode: http.StatusOK,
		},
		{
			name:         "head manifest",
			method:       "HEAD",
			path:         "/v2/repo1/manifests/latest",
			expectedCode: http.StatusOK,
		},
		{
			name:         "manifest not found",
			method:       "GET",
			path:         "/v2/repo1/manifests/missing",
			expectedCode: http.StatusNotFound,
		},
		{
			name:         "put manifest",
			method:       "PUT",
			path:         "/v2/repo1/manifests/newtag",
			body:         manifestBytes,
			expectedCode: http.StatusCreated,
		},
		{
			name:         "delete manifest",
			method:       "DELETE",
			path:         "/v2/repo1/manifests/latest",
			expectedCode: http.StatusAccepted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != nil {
				body = bytes.NewReader(tt.body)
			}
			req, err := http.NewRequest(tt.method, registry.URL()+tt.path, body)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			if tt.method == "PUT" {
				req.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to do request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, resp.StatusCode)
			}
		})
	}
}

func TestMockRegistry_Blobs(t *testing.T) {
	blobContent := []byte("test blob content")
	blobDigest := digest.FromBytes(blobContent)

	content := &RegistryContent{
		Repositories: map[string]*RepositoryContent{
			"repo1": {
				Blobs: map[string][]byte{
					blobDigest.String(): blobContent,
				},
			},
		},
	}
	registry := NewMockRegistry(content)
	defer registry.Close()

	tests := []struct {
		name         string
		method       string
		path         string
		headers      map[string]string
		expectedCode int
	}{
		{
			name:         "get blob",
			method:       "GET",
			path:         fmt.Sprintf("/v2/repo1/blobs/%s", blobDigest),
			expectedCode: http.StatusOK,
		},
		{
			name:         "head blob",
			method:       "HEAD",
			path:         fmt.Sprintf("/v2/repo1/blobs/%s", blobDigest),
			expectedCode: http.StatusOK,
		},
		{
			name:   "get blob with range",
			method: "GET",
			path:   fmt.Sprintf("/v2/repo1/blobs/%s", blobDigest),
			headers: map[string]string{
				"Range": "bytes=0-5",
			},
			expectedCode: http.StatusPartialContent,
		},
		{
			name:         "blob not found",
			method:       "GET",
			path:         "/v2/repo1/blobs/sha256:missing",
			expectedCode: http.StatusNotFound,
		},
		{
			name:         "delete blob",
			method:       "DELETE",
			path:         fmt.Sprintf("/v2/repo1/blobs/%s", blobDigest),
			expectedCode: http.StatusAccepted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, registry.URL()+tt.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to do request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, resp.StatusCode)
			}

			if tt.method == "GET" && tt.expectedCode == http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				if !bytes.Equal(body, blobContent) {
					t.Errorf("Expected blob content %q, got %q", blobContent, body)
				}
			}
		})
	}
}

func TestMockRegistry_BlobUpload(t *testing.T) {
	content := &RegistryContent{
		Repositories: map[string]*RepositoryContent{
			"repo1": {
				Blobs:        map[string][]byte{},
				Uploads:      map[string]*UploadState{},
				MinChunkSize: 5,
			},
		},
	}
	registry := NewMockRegistry(content)
	defer registry.Close()

	t.Run("chunked upload full flow", func(t *testing.T) {
		// Start upload
		resp, err := http.Post(registry.URL()+"/v2/repo1/blobs/uploads/", "", nil)
		if err != nil {
			t.Fatalf("Failed to start upload: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 202, got %d: %s", resp.StatusCode, string(body))
		}

		location := resp.Header.Get("Location")
		if location == "" {
			t.Fatal("No upload location returned")
		}

		// Verify empty upload state
		req, err := http.NewRequest(http.MethodGet, registry.URL()+location, nil)
		if err != nil {
			t.Fatalf("Failed to create GET request: %v", err)
		}
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to get upload state: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("Expected status 204, got %d", resp.StatusCode)
		}
		if resp.Header.Get("Range") != "0-0" {
			t.Errorf("Expected Range: 0-0, got %s", resp.Header.Get("Range"))
		}

		// Upload content in chunks
		content := []byte("test blob content")
		chunks := [][]byte{
			content[:5],
			content[5:10],
			content[10:],
		}

		// Upload chunks
		currentRange := 0
		for i, chunk := range chunks {
			req, err := http.NewRequest(http.MethodPatch, registry.URL()+location, bytes.NewReader(chunk))
			if err != nil {
				t.Fatalf("Failed to create PATCH request: %v", err)
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("Content-Range", fmt.Sprintf("%d-%d", currentRange, currentRange+len(chunk)-1))
			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to upload chunk %d: %v", i, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusAccepted {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("Chunk %d: expected status 202, got %d: %s", i, resp.StatusCode, string(body))
			}

			currentRange += len(chunk)
		}

		// Complete upload
		blobDigest := digest.FromBytes(content)
		completeURL := fmt.Sprintf("%s%s?digest=%s", registry.URL(), location, blobDigest)
		req, err = http.NewRequest(http.MethodPut, completeURL, nil)
		if err != nil {
			t.Fatalf("Failed to create PUT request: %v", err)
		}

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to complete upload: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		// Verify blob can be retrieved
		resp, err = http.Get(registry.URL() + fmt.Sprintf("/v2/repo1/blobs/%s", blobDigest))
		if err != nil {
			t.Fatalf("Failed to get blob: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		gotContent, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read blob content: %v", err)
		}

		if !bytes.Equal(gotContent, content) {
			t.Errorf("Expected content %q, got %q", content, gotContent)
		}
	})

	t.Run("monolithic upload", func(t *testing.T) {
		content := []byte("direct upload content")
		blobDigest := digest.FromBytes(content)

		// Direct upload with digest
		url := fmt.Sprintf("%s/v2/repo1/blobs/uploads/?digest=%s", registry.URL(), blobDigest)
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(content))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(content)))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to do request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		// Verify blob was stored
		resp, err = http.Get(registry.URL() + fmt.Sprintf("/v2/repo1/blobs/%s", blobDigest))
		if err != nil {
			t.Fatalf("Failed to get blob: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		gotContent, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read blob content: %v", err)
		}

		if !bytes.Equal(gotContent, content) {
			t.Errorf("Expected content %q, got %q", content, gotContent)
		}
	})

	t.Run("blob mount", func(t *testing.T) {
		// First upload a blob to repo2
		content := &RegistryContent{
			Repositories: map[string]*RepositoryContent{
				"repo1": {Blobs: map[string][]byte{}},
				"repo2": {Blobs: map[string][]byte{}},
			},
		}
		registry := NewMockRegistry(content)
		defer registry.Close()

		blobContent := []byte("blob to mount")
		blobDigest := digest.FromBytes(blobContent)

		// Upload to repo2
		url := fmt.Sprintf("%s/v2/repo2/blobs/uploads/?digest=%s", registry.URL(), blobDigest)
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(blobContent))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to do request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Failed to upload blob to source repo: %d", resp.StatusCode)
		}

		// Try to mount from repo2 to repo1
		url = fmt.Sprintf("%s/v2/repo1/blobs/uploads/?mount=%s&from=repo2", registry.URL(), blobDigest)
		req, err = http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to do request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			t.Errorf("Expected status 201, got %d", resp.StatusCode)
		}

		// Verify blob exists in repo1
		resp, err = http.Get(registry.URL() + fmt.Sprintf("/v2/repo1/blobs/%s", blobDigest))
		if err != nil {
			t.Fatalf("Failed to get blob: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid digest", func(t *testing.T) {
		content := []byte("invalid digest test")
		wrongDigest := "sha256:wrong"

		url := fmt.Sprintf("%s/v2/repo1/blobs/uploads/?digest=%s", registry.URL(), wrongDigest)
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(content))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to do request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", resp.StatusCode)
		}
	})

	t.Run("chunk size validation", func(t *testing.T) {
		// Start upload
		resp, err := http.Post(registry.URL()+"/v2/repo1/blobs/uploads/", "", nil)
		if err != nil {
			t.Fatalf("Failed to start upload: %v", err)
		}
		defer resp.Body.Close()

		location := resp.Header.Get("Location")
		if location == "" {
			t.Fatal("No upload location returned")
		}

		// Try to upload chunk smaller than MinChunkSize
		smallChunk := []byte("tiny")
		req, err := http.NewRequest(http.MethodPatch, registry.URL()+location, bytes.NewReader(smallChunk))
		if err != nil {
			t.Fatalf("Failed to create PATCH request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Range", fmt.Sprintf("0-%d", len(smallChunk)-1))

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to upload chunk: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
			t.Errorf("Expected status 416, got %d", resp.StatusCode)
		}
	})
}

func TestMockRegistry_Referrers(t *testing.T) {
	// Set up base manifest and blob
	imageLayerBytes := []byte("test layer content")
	imageLayerDigest := digest.FromBytes(imageLayerBytes)

	imageManifest := v1.Manifest{
		Versioned: v1.ManifestSchemaVersion,
		Config: descriptor.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    digest.FromString("test config"),
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
	imageBytes, _ := json.Marshal(imageManifest)
	imageDigest := digest.FromBytes(imageBytes)

	// Create various types of referrers
	sbomContent := []byte("test SBOM content")
	sbomDigest := digest.FromBytes(sbomContent)

	sigContent := []byte("test signature content")
	sigDigest := digest.FromBytes(sigContent)

	customContent := []byte("test custom artifact")
	customDigest := digest.FromBytes(customContent)

	content := &RegistryContent{
		Repositories: map[string]*RepositoryContent{
			"test-repo": {
				Manifests: map[string]ManifestContent{
					imageDigest.String(): {
						Content:   imageBytes,
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    imageDigest,
						Referrers: []descriptor.Descriptor{
							{
								MediaType:    "application/vnd.oci.image.manifest.v1+json",
								Digest:       sbomDigest,
								Size:         int64(len(sbomContent)),
								ArtifactType: "application/vnd.example.sbom.v1+json",
								Annotations: map[string]string{
									"org.opencontainers.image.created": "2024-01-01T00:00:00Z",
								},
							},
							{
								MediaType:    "application/vnd.oci.image.manifest.v1+json",
								Digest:       sigDigest,
								Size:         int64(len(sigContent)),
								ArtifactType: "application/vnd.example.signature.v1+json",
								Annotations: map[string]string{
									"org.opencontainers.image.created": "2024-01-01T00:00:00Z",
								},
							},
							{
								MediaType:    "application/vnd.oci.image.manifest.v1+json",
								Digest:       customDigest,
								Size:         int64(len(customContent)),
								ArtifactType: "application/vnd.example.custom.v1+json",
								Annotations: map[string]string{
									"org.opencontainers.image.created": "2024-01-01T00:00:00Z",
									"custom.metadata":                  "test value",
								},
							},
						},
					},
					sbomDigest.String(): {
						Content:      sbomContent,
						MediaType:    "application/vnd.oci.image.manifest.v1+json",
						Digest:       sbomDigest,
						ArtifactType: "application/vnd.example.sbom.v1+json",
					},
					sigDigest.String(): {
						Content:      sigContent,
						MediaType:    "application/vnd.oci.image.manifest.v1+json",
						Digest:       sigDigest,
						ArtifactType: "application/vnd.example.signature.v1+json",
					},
					customDigest.String(): {
						Content:      customContent,
						MediaType:    "application/vnd.oci.image.manifest.v1+json",
						Digest:       customDigest,
						ArtifactType: "application/vnd.example.custom.v1+json",
					},
				},
				Blobs: map[string][]byte{
					imageLayerDigest.String(): imageLayerBytes,
				},
			},
			"empty-repo": {
				Manifests: map[string]ManifestContent{},
				Blobs:     map[string][]byte{},
			},
		},
	}

	registry := NewMockRegistry(content)
	defer registry.Close()

	tests := []struct {
		name          string
		path          string
		query         string
		expectedCode  int
		validateResp  func(t *testing.T, body []byte)
		expectHeaders map[string]string
	}{
		{
			name:         "get all referrers",
			path:         fmt.Sprintf("/v2/test-repo/referrers/%s", imageDigest),
			expectedCode: http.StatusOK,
			validateResp: func(t *testing.T, body []byte) {
				var index v1.Index
				if err := json.Unmarshal(body, &index); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}
				if len(index.Manifests) != 3 {
					t.Errorf("Expected 3 referrers, got %d", len(index.Manifests))
				}
			},
			expectHeaders: map[string]string{
				"Content-Type": "application/vnd.oci.image.index.v1+json",
			},
		},
		{
			name:         "filter by artifact type",
			path:         fmt.Sprintf("/v2/test-repo/referrers/%s", imageDigest),
			query:        "?artifactType=application/vnd.example.sbom.v1%2Bjson",
			expectedCode: http.StatusOK,
			validateResp: func(t *testing.T, body []byte) {
				var index v1.Index
				if err := json.Unmarshal(body, &index); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}
				if len(index.Manifests) != 1 {
					t.Errorf("Expected 1 referrer, got %d", len(index.Manifests))
				}
				if index.Manifests[0].ArtifactType != "application/vnd.example.sbom.v1+json" {
					t.Errorf("Expected SBOM artifact type, got %s", index.Manifests[0].ArtifactType)
				}
			},
			expectHeaders: map[string]string{
				"Content-Type":        "application/vnd.oci.image.index.v1+json",
				"OCI-Filters-Applied": "artifactType",
			},
		},
		{
			name:         "referrers with invalid digest format",
			path:         "/v2/test-repo/referrers/invalid-digest",
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "nonexistent repository",
			path:         fmt.Sprintf("/v2/nonexistent/referrers/%s", imageDigest),
			expectedCode: http.StatusNotFound,
		},
		{
			name:         "empty repository",
			path:         fmt.Sprintf("/v2/empty-repo/referrers/%s", imageDigest),
			expectedCode: http.StatusOK,
			validateResp: func(t *testing.T, body []byte) {
				var index v1.Index
				if err := json.Unmarshal(body, &index); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}
				if len(index.Manifests) != 0 {
					t.Errorf("Expected empty referrers list, got %d entries", len(index.Manifests))
				}
			},
		},
		{
			name:         "manifest with no referrers",
			path:         fmt.Sprintf("/v2/test-repo/referrers/%s", sbomDigest),
			expectedCode: http.StatusOK,
			validateResp: func(t *testing.T, body []byte) {
				var index v1.Index
				if err := json.Unmarshal(body, &index); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}
				if len(index.Manifests) != 0 {
					t.Errorf("Expected empty referrers list, got %d entries", len(index.Manifests))
				}
			},
		},
		{
			name:         "validate required descriptor fields",
			path:         fmt.Sprintf("/v2/test-repo/referrers/%s", imageDigest),
			expectedCode: http.StatusOK,
			validateResp: func(t *testing.T, body []byte) {
				var index v1.Index
				if err := json.Unmarshal(body, &index); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}
				for _, m := range index.Manifests {
					if m.MediaType == "" {
						t.Error("MediaType is required")
					}
					if m.Digest == "" {
						t.Error("Digest is required")
					}
					if m.Size == 0 {
						t.Error("Size is required")
					}
					if m.ArtifactType == "" {
						t.Error("ArtifactType should be set")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := registry.URL() + tt.path
			if tt.query != "" {
				url += tt.query
			}

			resp, err := http.Get(url)
			if err != nil {
				t.Fatalf("Failed to send request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, resp.StatusCode)
			}

			if tt.validateResp != nil && resp.StatusCode == http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				tt.validateResp(t, body)
			}

			for header, expectedValue := range tt.expectHeaders {
				if got := resp.Header.Get(header); got != expectedValue {
					t.Errorf("Expected header %s=%s, got %s", header, expectedValue, got)
				}
			}
		})
	}

	// Test referrer deletion
	t.Run("referrer list update after manifest deletion", func(t *testing.T) {
		// First verify the SBOM referrer exists
		url := fmt.Sprintf("%s/v2/test-repo/referrers/%s", registry.URL(), imageDigest)
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("Failed to get referrers: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to get initial referrers: %d", resp.StatusCode)
		}

		// Delete the SBOM manifest
		url = fmt.Sprintf("%s/v2/test-repo/manifests/%s", registry.URL(), sbomDigest)
		req, err := http.NewRequest(http.MethodDelete, url, nil)
		if err != nil {
			t.Fatalf("Failed to create delete request: %v", err)
		}
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to delete manifest: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("Failed to delete manifest: %d", resp.StatusCode)
		}

		// Verify the SBOM is no longer in the referrers list
		url = fmt.Sprintf("%s/v2/test-repo/referrers/%s", registry.URL(), imageDigest)
		resp, err = http.Get(url)
		if err != nil {
			t.Fatalf("Failed to get referrers after delete: %v", err)
		}
		defer resp.Body.Close()

		var index v1.Index
		if err := json.NewDecoder(resp.Body).Decode(&index); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		for _, m := range index.Manifests {
			if m.Digest == sbomDigest {
				t.Error("SBOM manifest should not be in referrers list after deletion")
			}
		}
	})
}
