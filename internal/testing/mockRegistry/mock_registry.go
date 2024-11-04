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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/descriptor"
	v1 "github.com/regclient/regclient/types/oci/v1"
)

// RegistryContent represents the content stored in the mock registry
type RegistryContent struct {
	// Map of repository names to their content
	Repositories map[string]*RepositoryContent
	// Optional custom error responses
	ErrorResponses map[string]ErrorResponse
	// Optional custom headers for responses
	CustomHeaders map[string]map[string]string
}

// RepositoryContent represents content within a repository
type RepositoryContent struct {
	// Map of tag names to manifest digests
	Tags map[string]string
	// Map of manifest digests to their content
	Manifests map[string]ManifestContent
	// Map of blob digests to their content
	Blobs map[string][]byte
	// Map of upload UUIDs to their partial content
	Uploads map[string]*UploadState
	// Optional minimum chunk size for uploads
	MinChunkSize int64
}

// ManifestContent represents a manifest and its metadata
type ManifestContent struct {
	Content      []byte
	MediaType    string
	Digest       digest.Digest
	Referrers    []descriptor.Descriptor
	ArtifactType string
}

// UploadState tracks the state of a blob upload
type UploadState struct {
	Data        []byte
	Offset      int64
	ID          string
	DigestValue string
}

// ErrorResponse represents a custom error response
type ErrorResponse struct {
	Code       int
	ErrorCodes []ErrorCode
}

// ErrorCode represents an individual error in the response
type ErrorCode struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Detail  map[string]any `json:"detail,omitempty"`
}

// MockRegistry provides a mock OCI registry implementation (distribution-spec)
type MockRegistry struct {
	server  *httptest.Server
	content *RegistryContent
}

// NewMockRegistry creates a new mock registry server
func NewMockRegistry(content *RegistryContent) *MockRegistry {
	m := &MockRegistry{content: content}
	m.server = httptest.NewServer(m.handler())
	return m
}

// URL returns the URL of the mock registry
func (m *MockRegistry) URL() string {
	return m.server.URL
}

// Close shuts down the mock registry server
func (m *MockRegistry) Close() {
	m.server.Close()
}

func (m *MockRegistry) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for custom error responses first
		if m.content.ErrorResponses != nil {
			if errResp, exists := m.content.ErrorResponses[r.URL.Path]; exists {
				m.writeError(w, errResp.Code, errResp.ErrorCodes)
				return
			}
		}

		// Add custom headers if configured
		if m.content.CustomHeaders != nil {
			if headers, exists := m.content.CustomHeaders[r.URL.Path]; exists {
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}

		switch {
		case r.Method == "GET" && r.URL.Path == "/v2/":
			m.handleAPIVersion(w, r)
		case r.Method == "GET" && r.URL.Path == "/v2/_catalog":
			m.handleCatalog(w, r)
		case regexp.MustCompile(`^/v2/(.*)/tags/list`).MatchString(r.URL.Path):
			m.handleTagsList(w, r)
		case regexp.MustCompile(`^/v2/(.*)/manifests/(.*)`).MatchString(r.URL.Path):
			m.handleManifests(w, r)
		case regexp.MustCompile(`^/v2/(.*)/blobs/uploads/[a-zA-Z0-9-_]*$`).MatchString(r.URL.Path):
			if r.Method == "POST" {
				m.handleBlobUpload(w, r)
			} else {
				m.handleBlobUploadState(w, r)
			}
		case regexp.MustCompile(`^/v2/(.*)/blobs/uploads/`).MatchString(r.URL.Path):
			m.handleBlobUploadState(w, r)
		case regexp.MustCompile(`^/v2/(.*)/blobs/(.*)`).MatchString(r.URL.Path):
			m.handleBlobs(w, r)
		case regexp.MustCompile(`^/v2/(.*)/referrers/(.*)`).MatchString(r.URL.Path):
			m.handleReferrers(w, r)
		default:
			m.writeError(w, http.StatusNotFound, []ErrorCode{{
				Code:    "NAME_UNKNOWN",
				Message: "repository name not known to registry",
			}})
		}
	})
}

func (m *MockRegistry) handleAPIVersion(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *MockRegistry) handleCatalog(w http.ResponseWriter, r *http.Request) {
	repos := make([]string, 0, len(m.content.Repositories))
	for repo := range m.content.Repositories {
		repos = append(repos, repo)
	}

	response := struct {
		Repositories []string `json:"repositories"`
	}{
		Repositories: repos,
	}

	m.writeJSON(w, http.StatusOK, "", response)
}

func (m *MockRegistry) handleTagsList(w http.ResponseWriter, r *http.Request) {
	matches := regexp.MustCompile(`^/v2/(.*)/tags/list`).FindStringSubmatch(r.URL.Path)
	if len(matches) != 2 {
		m.writeError(w, http.StatusNotFound, []ErrorCode{{
			Code:    "NAME_UNKNOWN",
			Message: "repository name not known to registry",
		}})
		return
	}

	repoName := matches[1]
	repo, exists := m.content.Repositories[repoName]
	if !exists {
		m.writeError(w, http.StatusNotFound, []ErrorCode{{
			Code:    "NAME_UNKNOWN",
			Message: "repository name not known to registry",
		}})
		return
	}

	tags := make([]string, 0, len(repo.Tags))
	for tag := range repo.Tags {
		tags = append(tags, tag)
	}

	response := struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}{
		Name: repoName,
		Tags: tags,
	}

	m.writeJSON(w, http.StatusOK, "", response)
}

func (m *MockRegistry) handleManifests(w http.ResponseWriter, r *http.Request) {
	matches := regexp.MustCompile(`^/v2/(.*)/manifests/(.*)`).FindStringSubmatch(r.URL.Path)
	if len(matches) != 3 {
		m.writeError(w, http.StatusNotFound, []ErrorCode{{
			Code:    "NAME_UNKNOWN",
			Message: "repository name not known to registry",
		}})
		return
	}

	repoName := matches[1]
	reference := matches[2]

	repo, exists := m.content.Repositories[repoName]
	if !exists {
		m.writeError(w, http.StatusNotFound, []ErrorCode{{
			Code:    "NAME_UNKNOWN",
			Message: "repository name not known to registry",
		}})
		return
	}

	switch r.Method {
	case "GET", "HEAD":
		// Handle manifest retrieval by tag or digest
		var manifest ManifestContent
		if digest, err := digest.Parse(reference); err == nil {
			// Reference is a digest
			manifest = repo.Manifests[digest.String()]
		} else {
			// Reference is a tag
			digestStr, exists := repo.Tags[reference]
			if !exists {
				m.writeError(w, http.StatusNotFound, []ErrorCode{{
					Code:    "MANIFEST_UNKNOWN",
					Message: "manifest unknown to registry",
				}})
				return
			}
			manifest = repo.Manifests[digestStr]
		}

		w.Header().Set("Content-Type", manifest.MediaType)
		w.Header().Set("Docker-Content-Digest", manifest.Digest.String())
		if r.Method == "GET" {
			_, err := w.Write(manifest.Content)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		} else {
			w.WriteHeader(http.StatusOK)
		}

	case "PUT":
		// Handle manifest upload
		body, err := readAllBody(r)
		if err != nil {
			m.writeError(w, http.StatusBadRequest, []ErrorCode{{
				Code:    "MANIFEST_INVALID",
				Message: "failed to read manifest body",
			}})
			return
		}

		dgst := digest.FromBytes(body)
		manifest := ManifestContent{
			Content:   body,
			MediaType: r.Header.Get("Content-Type"),
			Digest:    dgst,
		}

		// Parse manifest to check for subject field
		var manifestObj struct {
			Subject *descriptor.Descriptor `json:"subject,omitempty"`
		}
		if err := json.Unmarshal(body, &manifestObj); err == nil && manifestObj.Subject != nil {
			w.Header().Set("OCI-Subject", manifestObj.Subject.Digest.String())
		}

		repo.Manifests[dgst.String()] = manifest
		if strings.Contains(reference, ":") {
			// Reference is likely a digest
		} else {
			repo.Tags[reference] = dgst.String()
		}

		w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repoName, dgst))
		w.WriteHeader(http.StatusCreated)

	case "DELETE":
		// Handle manifest deletion
		_, exists := repo.Manifests[reference]
		if !exists {
			delete(repo.Tags, reference)
		}

		if exists {
			// Delete the manifest
			delete(repo.Manifests, reference)

			// Remove this manifest from any referrers lists
			for _, otherManifest := range repo.Manifests {
				updatedReferrers := make([]descriptor.Descriptor, 0, len(otherManifest.Referrers))
				for _, ref := range otherManifest.Referrers {
					if ref.Digest.String() != reference {
						updatedReferrers = append(updatedReferrers, ref)
					}
				}
				otherManifest.Referrers = updatedReferrers
			}
		}
		w.WriteHeader(http.StatusAccepted)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *MockRegistry) handleReferrers(w http.ResponseWriter, r *http.Request) {
	matches := regexp.MustCompile(`^/v2/(.*)/referrers/(.*)`).FindStringSubmatch(r.URL.Path)
	if len(matches) != 3 {
		m.writeError(w, http.StatusBadRequest, []ErrorCode{{
			Code:    "NAME_INVALID",
			Message: "invalid repository name",
		}})
		return
	}

	repoName := matches[1]
	digestStr := matches[2]

	// Validate digest format
	if _, err := digest.Parse(digestStr); err != nil {
		m.writeError(w, http.StatusBadRequest, []ErrorCode{{
			Code:    "DIGEST_INVALID",
			Message: "invalid digest format",
		}})
		return
	}

	repo, exists := m.content.Repositories[repoName]
	if !exists {
		m.writeError(w, http.StatusNotFound, []ErrorCode{{
			Code:    "NAME_UNKNOWN",
			Message: "repository name not known to registry",
		}})
		return
	}

	manifest, exists := repo.Manifests[digestStr]
	if !exists {
		// Return empty list per spec
		index := v1.Index{
			Versioned: v1.ManifestSchemaVersion,
			MediaType: "application/vnd.oci.image.index.v1+json",
			Manifests: []descriptor.Descriptor{},
		}
		m.writeJSON(w, http.StatusOK, "application/vnd.oci.image.index.v1+json", index)
		return
	}

	// Build referrers list, excluding any manifests that have been deleted
	descriptors := make([]descriptor.Descriptor, 0, len(manifest.Referrers))
	for _, ref := range manifest.Referrers {
		// Only include referrer if it still exists in the repository
		if _, exists := repo.Manifests[ref.Digest.String()]; exists {
			descriptors = append(descriptors, ref)
		}
	}

	// Filter by artifactType if requested
	artifactType := r.URL.Query().Get("artifactType")
	if artifactType != "" {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
		filtered := make([]descriptor.Descriptor, 0)
		for _, ref := range descriptors {
			if ref.ArtifactType == artifactType {
				filtered = append(filtered, ref)
			}
		}
		descriptors = filtered
	}

	index := v1.Index{
		Versioned: v1.ManifestSchemaVersion,
		MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: descriptors,
	}

	m.writeJSON(w, http.StatusOK, "application/vnd.oci.image.index.v1+json", index)
}

// Helper functions for reading bodies and writing responses
func readAllBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func (m *MockRegistry) handleBlobs(w http.ResponseWriter, r *http.Request) {
	repoName, ok := extractRepoName(`^/v2/(.*)/blobs/(.*)`, r.URL.Path)
	if !ok {
		m.writeError(w, http.StatusBadRequest, []ErrorCode{{
			Code:    "NAME_INVALID",
			Message: "invalid repository name",
		}})
		return
	}

	repo, ok := m.getRepository(w, repoName)
	if !ok {
		return
	}

	matches := regexp.MustCompile(`^/v2/.*?/blobs/(.*)`).FindStringSubmatch(r.URL.Path)
	if len(matches) != 2 {
		m.writeError(w, http.StatusBadRequest, []ErrorCode{{
			Code:    "DIGEST_INVALID",
			Message: "invalid digest",
		}})
		return
	}
	digest := matches[1]

	switch r.Method {
	case "HEAD", "GET":
		blob, exists := repo.Blobs[digest]
		if !exists {
			m.writeError(w, http.StatusNotFound, []ErrorCode{{
				Code:    "BLOB_UNKNOWN",
				Message: "blob unknown to registry",
			}})
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(blob)))

		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Handle range requests
		rangeHeader := r.Header.Get("Range")
		if rangeHeader != "" {
			if err := m.handleBlobRange(w, r, blob); err != nil {
				m.writeError(w, http.StatusRequestedRangeNotSatisfiable, []ErrorCode{{
					Code:    "UNSUPPORTED",
					Message: "invalid range request",
				}})
				return
			}
			return
		}

		w.WriteHeader(http.StatusOK)
		_, err := w.Write(blob)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

	case "DELETE":
		_, exists := repo.Blobs[digest]
		if !exists {
			m.writeError(w, http.StatusNotFound, []ErrorCode{{
				Code:    "BLOB_UNKNOWN",
				Message: "blob unknown to registry",
			}})
			return
		}
		delete(repo.Blobs, digest)
		w.WriteHeader(http.StatusAccepted)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *MockRegistry) handleBlobRange(w http.ResponseWriter, r *http.Request, blob []byte) error {
	ranges, err := parseRangeHeader(r.Header.Get("Range"), int64(len(blob)))
	if err != nil {
		return err
	}

	// We'll handle only the first range for simplicity
	if len(ranges) > 0 {
		rng := ranges[0]
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rng.Start, rng.End, len(blob)))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", rng.End-rng.Start+1))
		w.WriteHeader(http.StatusPartialContent)
		_, err := w.Write(blob[rng.Start : rng.End+1])
		return err
	}
	return fmt.Errorf("no valid ranges")
}

func (m *MockRegistry) handleBlobUpload(w http.ResponseWriter, r *http.Request) {
	repoName, ok := extractRepoName(`^/v2/([^/]+)/blobs/uploads/`, r.URL.Path)
	if !ok {
		m.writeError(w, http.StatusBadRequest, []ErrorCode{{
			Code:    "NAME_INVALID",
			Message: "invalid repository name",
		}})
		return
	}

	repo, ok := m.getRepository(w, repoName)
	if !ok {
		return
	}

	switch r.Method {
	case "POST":
		// Handle mount request if specified
		if mountDigest := r.URL.Query().Get("mount"); mountDigest != "" {
			fromRepo := r.URL.Query().Get("from")
			if m.handleBlobMount(w, repoName, fromRepo, mountDigest) {
				return
			}
			// Mount failed, fall through to regular upload
		}

		// Handle single POST upload if digest is specified
		if digest := r.URL.Query().Get("digest"); digest != "" {
			m.handleMonolithicUpload(w, r, repo, repoName, digest)
			return
		}

		// Initialize chunked upload
		uploadID := generateUploadID()
		location := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repoName, uploadID)

		if repo.Uploads == nil {
			repo.Uploads = make(map[string]*UploadState)
		}

		repo.Uploads[uploadID] = &UploadState{
			Data:   make([]byte, 0),
			Offset: 0,
			ID:     uploadID,
		}

		w.Header().Set("Location", location)
		w.Header().Set("Range", "0-0")
		if repo.MinChunkSize > 0 {
			w.Header().Set("OCI-Chunk-Min-Length", fmt.Sprintf("%d", repo.MinChunkSize))
		}
		w.WriteHeader(http.StatusAccepted)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *MockRegistry) handleBlobUploadState(w http.ResponseWriter, r *http.Request) {
	repoName, ok := extractRepoName(`^/v2/([^/]+)/blobs/uploads/`, r.URL.Path)
	if !ok {
		m.writeError(w, http.StatusBadRequest, []ErrorCode{{
			Code:    "NAME_INVALID",
			Message: "invalid repository name",
		}})
		return
	}

	repo, ok := m.getRepository(w, repoName)
	if !ok {
		return
	}

	matches := regexp.MustCompile(`^/v2/.*?/blobs/uploads/(.*)`).FindStringSubmatch(r.URL.Path)
	if len(matches) != 2 {
		m.writeError(w, http.StatusBadRequest, []ErrorCode{{
			Code:    "BLOB_UPLOAD_INVALID",
			Message: "invalid upload ID",
		}})
		return
	}
	uploadID := matches[1]

	uploadState, exists := repo.Uploads[uploadID]
	if !exists {
		m.writeError(w, http.StatusNotFound, []ErrorCode{{
			Code:    "BLOB_UPLOAD_UNKNOWN",
			Message: "upload unknown to registry",
		}})
		return
	}

	switch r.Method {
	case "GET":
		// Return current upload status
		w.Header().Set("Docker-Upload-UUID", uploadID)
		if uploadState.Offset == 0 {
			w.Header().Set("Range", "0-0")
		} else {
			w.Header().Set("Range", fmt.Sprintf("0-%d", uploadState.Offset-1))
		}
		w.WriteHeader(http.StatusNoContent)

	case "PATCH":
		// Handle chunk upload
		contentRange := r.Header.Get("Content-Range")
		if contentRange != "" {
			if err := m.handleChunkUpload(w, r, repo, uploadState); err != nil {
				m.writeError(w, http.StatusRequestedRangeNotSatisfiable, []ErrorCode{{
					Code:    "BLOB_UPLOAD_INVALID",
					Message: err.Error(),
				}})
				return
			}
		} else {
			// Append chunk to end
			chunk, err := readAllBody(r)
			if err != nil {
				m.writeError(w, http.StatusBadRequest, []ErrorCode{{
					Code:    "BLOB_UPLOAD_INVALID",
					Message: "failed to read upload body",
				}})
				return
			}

			uploadState.Data = append(uploadState.Data, chunk...)
			uploadState.Offset = int64(len(uploadState.Data))
		}

		w.Header().Set("Location", r.URL.Path)
		w.Header().Set("Range", fmt.Sprintf("0-%d", uploadState.Offset-1))
		w.Header().Set("Docker-Upload-UUID", uploadID)
		w.WriteHeader(http.StatusAccepted)

	case "PUT":
		// Complete upload
		digestStr := r.URL.Query().Get("digest")
		if digestStr == "" {
			m.writeError(w, http.StatusBadRequest, []ErrorCode{{
				Code:    "DIGEST_INVALID",
				Message: "digest parameter missing",
			}})
			return
		}

		// Handle final chunk if provided
		if r.ContentLength > 0 {
			chunk, err := readAllBody(r)
			if err != nil {
				m.writeError(w, http.StatusBadRequest, []ErrorCode{{
					Code:    "BLOB_UPLOAD_INVALID",
					Message: "failed to read upload body",
				}})
				return
			}
			uploadState.Data = append(uploadState.Data, chunk...)
		}

		// Verify digest
		computedDigest := digest.FromBytes(uploadState.Data)
		if computedDigest.String() != digestStr {
			m.writeError(w, http.StatusBadRequest, []ErrorCode{{
				Code:    "DIGEST_INVALID",
				Message: "provided digest does not match uploaded content",
			}})
			return
		}

		// Store blob
		repo.Blobs[digestStr] = uploadState.Data
		delete(repo.Uploads, uploadID)

		w.Header().Set("Docker-Content-Digest", digestStr)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repoName, digestStr))
		w.WriteHeader(http.StatusCreated)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *MockRegistry) handleBlobMount(w http.ResponseWriter, targetRepo string, sourceRepo string, digest string) bool {
	if sourceRepo == "" {
		// Try to find blob in any repository
		for repoName, repo := range m.content.Repositories {
			if repoName == targetRepo {
				continue
			}
			if blob, exists := repo.Blobs[digest]; exists {
				m.content.Repositories[targetRepo].Blobs[digest] = blob
				w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", targetRepo, digest))
				w.WriteHeader(http.StatusCreated)
				return true
			}
		}
		return false
	}

	sourceRepoContent, exists := m.content.Repositories[sourceRepo]
	if !exists {
		return false
	}

	blob, exists := sourceRepoContent.Blobs[digest]
	if !exists {
		return false
	}

	m.content.Repositories[targetRepo].Blobs[digest] = blob
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", targetRepo, digest))
	w.WriteHeader(http.StatusCreated)
	return true
}

func (m *MockRegistry) handleMonolithicUpload(w http.ResponseWriter, r *http.Request, repo *RepositoryContent, repoName string, digestStr string) {
	body, err := readAllBody(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, []ErrorCode{{
			Code:    "BLOB_UPLOAD_INVALID",
			Message: "failed to read upload body",
		}})
		return
	}

	computedDigest := digest.FromBytes(body)
	if computedDigest.String() != digestStr {
		m.writeError(w, http.StatusBadRequest, []ErrorCode{{
			Code:    "DIGEST_INVALID",
			Message: "provided digest does not match uploaded content",
		}})
		return
	}

	repo.Blobs[digestStr] = body
	w.Header().Set("Docker-Content-Digest", digestStr)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repoName, digestStr))
	w.WriteHeader(http.StatusCreated)
}

func (m *MockRegistry) handleChunkUpload(w http.ResponseWriter, r *http.Request, repo *RepositoryContent, uploadState *UploadState) error {
	// Parse Content-Range header
	contentRange := r.Header.Get("Content-Range")
	matches := regexp.MustCompile(`^([0-9]+)-([0-9]+)$`).FindStringSubmatch(contentRange)
	if len(matches) != 3 {
		return fmt.Errorf("invalid Content-Range format")
	}

	start, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid start position in Content-Range")
	}

	end, err := strconv.ParseInt(matches[2], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid end position in Content-Range")
	}

	// Validate range
	if start > end {
		return fmt.Errorf("invalid range: start position greater than end position")
	}

	// Validate chunk size if minimum is specified
	chunkSize := end - start + 1
	if repo.MinChunkSize > 0 && chunkSize < repo.MinChunkSize {
		return fmt.Errorf("chunk size %d is smaller than minimum allowed size %d", chunkSize, repo.MinChunkSize)
	}

	// Verify the range starts at the current offset
	if start != uploadState.Offset {
		return fmt.Errorf("invalid range: expected start position %d, got %d", uploadState.Offset, start)
	}

	// Read chunk data
	chunk, err := readAllBody(r)
	if err != nil {
		return fmt.Errorf("failed to read chunk data: %v", err)
	}

	// Verify chunk size matches Content-Range
	if int64(len(chunk)) != chunkSize {
		return fmt.Errorf("chunk size %d does not match Content-Range size %d", len(chunk), chunkSize)
	}

	// Handle first chunk
	if start == 0 {
		uploadState.Data = chunk
	} else {
		// Append chunk to existing data
		// Ensure we have enough capacity
		if int64(len(uploadState.Data)) < end+1 {
			newData := make([]byte, end+1)
			copy(newData, uploadState.Data)
			uploadState.Data = newData
		}
		copy(uploadState.Data[start:], chunk)
	}

	uploadState.Offset = end + 1
	return nil
}

// Helper function to extract repository name from a path pattern
func extractRepoName(pattern string, path string) (string, bool) {
	matches := regexp.MustCompile(pattern).FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

func (m *MockRegistry) writeJSON(w http.ResponseWriter, status int, contentType string, v interface{}) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (m *MockRegistry) writeError(w http.ResponseWriter, status int, errors []ErrorCode) {
	response := struct {
		Errors []ErrorCode `json:"errors"`
	}{
		Errors: errors,
	}
	m.writeJSON(w, status, "", response)
}

// Helper function to look up repository
func (m *MockRegistry) getRepository(w http.ResponseWriter, repoName string) (*RepositoryContent, bool) {
	repo, exists := m.content.Repositories[repoName]
	if !exists {
		m.writeError(w, http.StatusNotFound, []ErrorCode{{
			Code:    "NAME_UNKNOWN",
			Message: "repository name not known to registry",
		}})
		return nil, false
	}
	return repo, true
}

// Helper function to generate unique upload IDs
func generateUploadID() string {
	return fmt.Sprintf("upload-%d", time.Now().UnixNano())
}

// Range represents a byte range
type Range struct {
	Start, End int64
}

// parseRangeHeader parses the Range header string
func parseRangeHeader(rangeHeader string, size int64) ([]Range, error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, fmt.Errorf("invalid range header format")
	}

	var ranges []Range
	for _, rng := range strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), ",") {
		r, err := parseRange(strings.TrimSpace(rng), size)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	return ranges, nil
}

// parseRange parses a single range value
func parseRange(r string, size int64) (Range, error) {
	parts := strings.Split(r, "-")
	if len(parts) != 2 {
		return Range{}, fmt.Errorf("invalid range format")
	}

	start, end := int64(-1), int64(-1)
	if parts[0] != "" {
		s, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return Range{}, err
		}
		start = s
	}
	if parts[1] != "" {
		e, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return Range{}, err
		}
		end = e
	}

	if start == -1 {
		if end == -1 {
			return Range{}, fmt.Errorf("invalid range: both start and end are missing")
		}
		// suffix-length case: -500 means last 500 bytes
		start = size - end
		end = size - 1
	} else {
		if end == -1 {
			end = size - 1
		}
	}

	if start < 0 || end < 0 || start > end || end >= size {
		return Range{}, fmt.Errorf("invalid range: out of bounds")
	}

	return Range{Start: start, End: end}, nil
}
