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

package vexhub

import (
	"archive/tar"
	"bytes"
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
	packageurl "github.com/package-url/packageurl-go"
	"golang.org/x/time/rate"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	DefaultManifestURL = "https://raw.githubusercontent.com/aquasecurity/vexhub/main/vex-repository.json"
	VEXHubCollector    = "vexhub_certifier"
	rateLimit          = 100

	// httpTimeout is the deadline for any single HTTP request made by the certifier.
	// This prevents goroutine pinning when the archive endpoint stalls.
	httpTimeout = 5 * time.Minute

	// maxArchiveBytes is the total cumulative bytes we will buffer from the archive.
	// Prevents OOM when the hub grows large (tar-bomb protection).
	maxArchiveBytes = 512 * 1024 * 1024 // 512 MiB

	// maxEntryBytes is the per-file byte limit applied via io.LimitReader.
	maxEntryBytes = 32 * 1024 * 1024 // 32 MiB

	// supportedSpecVersion is the only spec version we know how to parse.
	// Forward-incompatible versions are logged and skipped.
	supportedSpecVersion = "0.1"
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
	// Set an explicit Timeout so a stalled archive endpoint cannot pin the
	// certifier goroutine indefinitely (P0 fix #2).
	client := &http.Client{
		Transport: transport,
		Timeout:   httpTimeout,
	}
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

	archiveURL, subdir := getArchiveURL(logger, manifest)
	if archiveURL == "" {
		logger.Infof("no compatible archive location found in VEX Hub manifest")
		return nil
	}

	// Download and extract the archive, building a canonical-PURL→VEX doc map.
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

// getArchiveURL extracts the archive URL and optional subdirectory from the manifest,
// selecting only entries whose spec_version matches supportedSpecVersion.
// The subdirectory is specified after "//" in the URL (per VEX Repo Spec).
// Example: "https://example.com/archive.tar.gz//vexhub-main" → URL + subdir "vexhub-main"
//
// Forward-incompatible spec versions are logged and skipped to avoid silently
// downloading archives that this parser cannot handle (P1 fix #2).
func getArchiveURL(logger interface{ Infof(string, ...interface{}) }, manifest *Manifest) (archiveURL, subdir string) {
	if len(manifest.Versions) == 0 {
		return "", ""
	}
	for _, v := range manifest.Versions {
		if v.SpecVersion != supportedSpecVersion {
			logger.Infof("VEX Hub: skipping unsupported spec_version %q (supported: %q)", v.SpecVersion, supportedSpecVersion)
			continue
		}
		if len(v.Locations) == 0 {
			continue
		}
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
	return "", ""
}

// canonicalizePURL parses a PURL with packageurl-go and re-stringifies it so
// that qualifier ordering, namespace casing, and percent-encoding are all
// normalised before map keying (P1 fix #1).
// Returns the original string unchanged if parsing fails.
func canonicalizePURL(purl string) string {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return purl
	}
	return p.ToString()
}

// downloadAndIndex downloads a tar.gz archive, uses a two-pass approach to
// safely extract only the files referenced in index.json, and returns a map
// of canonical-PURL → VEX document bytes.
//
// Two-pass design (P0 fix #1):
//  1. Stream the archive once, buffering only index.json and recording the
//     names of files referenced by index.Packages.
//  2. Stream the archive a second time (from the in-memory copy), reading
//     only those referenced files, each wrapped in io.LimitReader.
//
// This prevents unbounded memory growth (tar-bomb / OOM) as the hub scales.
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

	// Buffer the entire compressed archive so we can make two passes over it.
	// We cap the raw download at maxArchiveBytes to avoid OOM from a huge tarball.
	limitedBody := io.LimitReader(resp.Body, maxArchiveBytes+1)
	archiveData, err := io.ReadAll(limitedBody)
	if err != nil {
		return nil, fmt.Errorf("buffering archive: %w", err)
	}
	if int64(len(archiveData)) > maxArchiveBytes {
		return nil, fmt.Errorf("archive exceeds maximum allowed size of %d bytes", maxArchiveBytes)
	}

	// normalizeName strips the subdir prefix and the leading top-level directory
	// component (e.g. "vexhub-main/") from a tar entry name.
	normalizeName := func(name string) string {
		if subdir != "" {
			if after, found := strings.CutPrefix(name, subdir+"/"); found {
				name = after
			} else if after, found := strings.CutPrefix(name, subdir); found {
				name = after
			}
		}
		if subdir == "" {
			if idx := strings.Index(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}
		}
		return name
	}

	// openTar returns a fresh *tar.Reader over the buffered archive bytes.
	openTar := func() (*tar.Reader, error) {
		gz, err := gzip.NewReader(bytes.NewReader(archiveData))
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader: %w", err)
		}
		return tar.NewReader(gz), nil
	}

	// ── Pass 1: find and parse index.json only ────────────────────────────────
	tr1, err := openTar()
	if err != nil {
		return nil, err
	}
	var indexData []byte
	for {
		header, err := tr1.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar entry (pass 1): %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if normalizeName(header.Name) == "index.json" {
			indexData, err = io.ReadAll(io.LimitReader(tr1, maxEntryBytes))
			if err != nil {
				return nil, fmt.Errorf("reading index.json: %w", err)
			}
			break
		}
	}
	if indexData == nil {
		return nil, fmt.Errorf("index.json not found in archive")
	}

	var index Index
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, fmt.Errorf("parsing index.json: %w", err)
	}

	// Build the set of file paths we actually need.
	needed := make(map[string]bool, len(index.Packages))
	for _, pkg := range index.Packages {
		needed[pkg.Location] = true
	}

	// ── Pass 2: read only the referenced files ────────────────────────────────
	tr2, err := openTar()
	if err != nil {
		return nil, err
	}
	fileContents := make(map[string][]byte, len(needed))
	var cumulativeBytes int64
	for {
		header, err := tr2.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar entry (pass 2): %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := normalizeName(header.Name)
		if !needed[name] {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr2, maxEntryBytes))
		if err != nil {
			return nil, fmt.Errorf("reading file %s: %w", header.Name, err)
		}
		cumulativeBytes += int64(len(data))
		if cumulativeBytes > maxArchiveBytes {
			return nil, fmt.Errorf("extracted content exceeds maximum allowed size of %d bytes", maxArchiveBytes)
		}
		fileContents[name] = data
	}

	// Build canonical-PURL → VEX doc map.
	vexDocs := make(map[string][]byte, len(index.Packages))
	for _, pkg := range index.Packages {
		docData, ok := fileContents[pkg.Location]
		if !ok {
			continue
		}
		// Canonicalize the PURL from the index so lookups are consistent.
		vexDocs[canonicalizePURL(pkg.ID)] = docData
	}

	return vexDocs, nil
}

// emitVEXDocuments looks up each PURL in the VEX index and emits matching documents.
// Both the query PURLs and the index keys are canonicalized via packageurl-go
// before comparison so that PURL spelling variants do not cause misses (P1 fix #1).
func emitVEXDocuments(purls []string, vexDocs map[string][]byte, docChannel chan<- *processor.Document) ([]*processor.Document, error) {
	var emitted []*processor.Document
	seen := make(map[string]bool)

	for _, purl := range purls {
		if strings.Contains(purl, "pkg:guac") {
			continue
		}

		// Canonicalize the query PURL so qualifier order, namespace casing, and
		// percent-encoding all match the canonicalized index keys built in
		// downloadAndIndex.
		lookupKey := canonicalizePURL(purl)

		docData, ok := vexDocs[lookupKey]
		if !ok {
			// If an exact (canonicalized) match is not found, try without version
			// by zeroing the Version field and re-stringifying.
			p, err := packageurl.FromString(purl)
			if err == nil {
				p.Version = ""
				p.Qualifiers = packageurl.Qualifiers{}
				p.Subpath = ""
				lookupKey = p.ToString()
				docData, ok = vexDocs[lookupKey]
			}
		}

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
