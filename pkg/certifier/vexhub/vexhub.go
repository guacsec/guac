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

package vexhub

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/clients"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"

	jsoniter "github.com/json-iterator/go"
	"golang.org/x/time/rate"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	DefaultManifestURL = "https://raw.githubusercontent.com/aquasecurity/vexhub/main/vex-repository.json"
	VEXHubCollector    = "vexhub_certifier"
	rateLimit          = 100
)

var rateLimitInterval = time.Second

var ErrComponentTypeMismatch = errors.New("rootComponent type is not []*root_package.PackageNode")

// Manifest represents a vex-repository.json file.
type Manifest struct {
	Name     string            `json:"name"`
	Versions []ManifestVersion `json:"versions"`
}

// ManifestVersion holds the spec version and locations of a VEX repo.
type ManifestVersion struct {
	SpecVersion    string             `json:"spec_version"`
	Locations      []ManifestLocation `json:"locations"`
	UpdateInterval string             `json:"update_interval"`
}

// ManifestLocation holds the URL for a VEX repo archive.
type ManifestLocation struct {
	URL string `json:"url"`
}

// Index represents the index.json file inside the VEX repo archive.
type Index struct {
	UpdatedAt string         `json:"updated_at"`
	Packages  []IndexPackage `json:"packages"`
}

// IndexPackage maps a PURL to its VEX document location.
type IndexPackage struct {
	ID       string `json:"id"`
	Location string `json:"location"`
	Format   string `json:"format,omitempty"`
}

// vexHubCertifier queries VEX repositories for VEX statements.
type vexHubCertifier struct {
	httpClient  *http.Client
	manifestURL string
}

// NewVEXHubCertifier creates a new VEX Hub certifier.
func NewVEXHubCertifier(manifestURL string) certifier.Certifier {
	limiter := rate.NewLimiter(rate.Every(rateLimitInterval), rateLimit)
	transport := clients.NewRateLimitedTransport(version.UATransport, limiter)
	client := &http.Client{Transport: transport}
	if manifestURL == "" {
		manifestURL = DefaultManifestURL
	}
	return &vexHubCertifier{
		httpClient:  client,
		manifestURL: manifestURL,
	}
}

// CertifyComponent fetches VEX documents from the VEX Hub for the given packages.
func (v *vexHubCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return ErrComponentTypeMismatch
	}

	var purls []string
	for _, node := range packageNodes {
		purls = append(purls, node.Purl)
	}

	if len(purls) == 0 {
		return nil
	}

	// Fetch the manifest to get the archive URL.
	manifest, err := fetchManifest(ctx, v.httpClient, v.manifestURL)
	if err != nil {
		return fmt.Errorf("failed to fetch VEX Hub manifest: %w", err)
	}

	archiveURL, subdir := getArchiveURL(manifest)
	if archiveURL == "" {
		logger.Infof("no archive location found in VEX Hub manifest")
		return nil
	}

	// Download and extract the archive, building a PURL→VEX doc map.
	vexDocs, err := downloadAndIndex(ctx, v.httpClient, archiveURL, subdir)
	if err != nil {
		return fmt.Errorf("failed to download VEX Hub archive: %w", err)
	}

	logger.Infof("VEX Hub: indexed %d packages from archive", len(vexDocs))

	// Look up each PURL and emit matching VEX documents.
	if _, err := emitVEXDocuments(purls, vexDocs, docChannel); err != nil {
		return fmt.Errorf("failed to emit VEX documents: %w", err)
	}

	return nil
}

// fetchManifest downloads and parses the vex-repository.json manifest.
func fetchManifest(ctx context.Context, client *http.Client, url string) (*Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching manifest: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest fetch returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading manifest body: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return &manifest, nil
}

// getArchiveURL extracts the archive URL and optional subdirectory from the manifest.
// The subdirectory is specified after "//" in the URL (per VEX Repo Spec).
// Example: "https://example.com/archive.tar.gz//vexhub-main" → URL + subdir "vexhub-main"
func getArchiveURL(manifest *Manifest) (archiveURL, subdir string) {
	if len(manifest.Versions) == 0 {
		return "", ""
	}
	// Use the first version with a location.
	for _, v := range manifest.Versions {
		if len(v.Locations) > 0 {
			rawURL := v.Locations[0].URL
			// Look for "//" that is NOT part of the scheme (e.g., "https://").
			// The subdirectory separator always appears after the host/path portion.
			schemeEnd := strings.Index(rawURL, "://")
			searchStart := 0
			if schemeEnd >= 0 {
				searchStart = schemeEnd + 3
			}
			rest := rawURL[searchStart:]
			if idx := strings.Index(rest, "//"); idx >= 0 {
				archiveURL = rawURL[:searchStart+idx]
				subdir = rest[idx+2:]
			} else {
				archiveURL = rawURL
			}
			return archiveURL, subdir
		}
	}
	return "", ""
}

// downloadAndIndex downloads a tar.gz archive, extracts it, parses index.json,
// and returns a map of PURL→VEX document bytes.
func downloadAndIndex(ctx context.Context, client *http.Client, archiveURL, subdir string) (map[string][]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating archive request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("archive download returned status %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)

	// First pass: extract all files into memory.
	files := make(map[string][]byte)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar entry: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("reading file %s: %w", header.Name, err)
		}

		// Normalize path: strip the subdir prefix if present.
		name := header.Name
		if subdir != "" {
			if after, found := strings.CutPrefix(name, subdir+"/"); found {
				name = after
			} else if after, found := strings.CutPrefix(name, subdir); found {
				name = after
			}
		}
		// Also strip leading directory component from tar (e.g., "vexhub-main/")
		if idx := strings.Index(name, "/"); idx >= 0 {
			// Keep the path after the first directory component only if subdir wasn't already stripped.
			if subdir == "" {
				name = name[idx+1:]
			}
		}
		if name != "" {
			files[name] = data
		}
	}

	// Parse index.json.
	indexData, ok := files["index.json"]
	if !ok {
		return nil, fmt.Errorf("index.json not found in archive")
	}

	var index Index
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, fmt.Errorf("parsing index.json: %w", err)
	}

	// Build PURL→VEX doc map.
	vexDocs := make(map[string][]byte, len(index.Packages))
	for _, pkg := range index.Packages {
		docData, ok := files[pkg.Location]
		if !ok {
			continue
		}
		vexDocs[pkg.ID] = docData
	}

	return vexDocs, nil
}

// emitVEXDocuments looks up each PURL in the VEX index and emits matching documents.
func emitVEXDocuments(purls []string, vexDocs map[string][]byte, docChannel chan<- *processor.Document) ([]*processor.Document, error) {
	var emitted []*processor.Document
	seen := make(map[string]bool)

	for _, purl := range purls {
		if strings.Contains(purl, "pkg:guac") {
			continue
		}

		// Try exact PURL match first, then strip version for lookup.
		lookupKey := purl
		if _, ok := vexDocs[lookupKey]; !ok {
			lookupKey = stripPurlVersion(purl)
		}

		docData, ok := vexDocs[lookupKey]
		if !ok {
			continue
		}

		if seen[lookupKey] {
			continue
		}
		seen[lookupKey] = true

		doc := &processor.Document{
			Blob:   docData,
			Type:   processor.DocumentOpenVEX,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector:   VEXHubCollector,
				Source:      VEXHubCollector,
				DocumentRef: events.GetDocRef(docData),
			},
		}
		if docChannel != nil {
			docChannel <- doc
		}
		emitted = append(emitted, doc)
	}

	return emitted, nil
}

// stripPurlVersion removes the version, qualifiers, and subpath from a PURL.
// e.g. "pkg:npm/lodash@4.17.21" → "pkg:npm/lodash"
func stripPurlVersion(purl string) string {
	// Remove subpath (after last #)
	if idx := strings.Index(purl, "#"); idx >= 0 {
		purl = purl[:idx]
	}
	// Remove qualifiers (after ?)
	if idx := strings.Index(purl, "?"); idx >= 0 {
		purl = purl[:idx]
	}
	// Remove version (after @)
	if idx := strings.LastIndex(purl, "@"); idx >= 0 {
		purl = purl[:idx]
	}
	return purl
}
