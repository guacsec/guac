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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"

	jsoniter "github.com/json-iterator/go"
	packageurl "github.com/package-url/packageurl-go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	DefaultManifestURL = "https://raw.githubusercontent.com/aquasecurity/vexhub/main/vex-repository.json"
	VEXHubCollector    = "vexhub_certifier"

	// httpTimeout is the deadline for any single HTTP request made by the certifier.
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

type vexHubCertifier struct {
	httpClient  *http.Client
	manifestURL string

	// cache stores parsed manifest + vexDocs keyed by manifest URL, with TTL
	// derived from the manifest's update_interval field.
	cache   map[string]*manifestCacheEntry
	cacheMu sync.RWMutex

	// seen tracks which canonical PURLs have already been emitted so that
	// duplicate documents are not sent across subsequent CertifyComponent batches.
	seen   map[string]struct{}
	seenMu sync.Mutex
}

type manifestCacheEntry struct {
	manifest *Manifest
	vexDocs  map[string][]byte
	expiry   time.Time
}

// NewVEXHubCertifier creates a new VEX Hub certifier.
func NewVEXHubCertifier(manifestURL string) certifier.Certifier {
	if manifestURL == "" {
		manifestURL = DefaultManifestURL
	}
	return &vexHubCertifier{
		httpClient:  &http.Client{Timeout: httpTimeout},
		manifestURL: manifestURL,
		cache:       make(map[string]*manifestCacheEntry),
		seen:        make(map[string]struct{}),
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

	// Return cached vexDocs if they are still fresh.
	var vexDocs map[string][]byte
	v.cacheMu.RLock()
	entry, cached := v.cache[v.manifestURL]
	v.cacheMu.RUnlock()
	if cached && time.Now().Before(entry.expiry) {
		vexDocs = entry.vexDocs
	} else {
		// Fetch the manifest to discover archive locations.
		manifest, err := fetchManifest(ctx, v.httpClient, v.manifestURL)
		if err != nil {
			return fmt.Errorf("failed to fetch VEX Hub manifest: %w", err)
		}

		archiveURL, subdir := getArchiveURL(ctx, v.httpClient, manifest)
		if archiveURL == "" {
			logger.Infof("no compatible archive location found in VEX Hub manifest")
			return nil
		}

		vexDocs, err = downloadAndIndex(ctx, v.httpClient, archiveURL, subdir)
		if err != nil {
			return err
		}

		// Use update_interval from the matching manifest version as the TTL.
		ttl := time.Hour // safe default when update_interval is absent or unparseable
		for _, ver := range manifest.Versions {
			if ver.SpecVersion == supportedSpecVersion && ver.UpdateInterval != "" {
				if d, perr := time.ParseDuration(ver.UpdateInterval); perr == nil {
					ttl = d
				}
				break
			}
		}

		v.cacheMu.Lock()
		v.cache[v.manifestURL] = &manifestCacheEntry{
			manifest: manifest,
			vexDocs:  vexDocs,
			expiry:   time.Now().Add(ttl),
		}
		v.cacheMu.Unlock()
	}

	logger.Infof("VEX Hub: indexed %d packages from archive", len(vexDocs))

	if _, err := v.emitVEXDocuments(ctx, purls, vexDocs, docChannel); err != nil {
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

// getArchiveURL iterates over every version and every location in the manifest,
// selecting the first URL whose spec_version matches supportedSpecVersion and
// that responds to a HEAD request with HTTP 200.
//
// The subdirectory is specified after "//" in the URL (per VEX Repo Spec).
// Example: "https://example.com/archive.tar.gz//vexhub-main" -> archiveURL + subdir "vexhub-main"
//
// Versions with unsupported spec_version values are logged and skipped.
func getArchiveURL(ctx context.Context, client *http.Client, manifest *Manifest) (archiveURL, subdir string) {
	if len(manifest.Versions) == 0 {
		return "", ""
	}
	logger := logging.FromContext(ctx)
	for _, v := range manifest.Versions {
		if v.SpecVersion != supportedSpecVersion {
			logger.Infof("VEX Hub: skipping unsupported spec_version %q (supported: %q)", v.SpecVersion, supportedSpecVersion)
			continue
		}
		if len(v.Locations) == 0 {
			continue
		}
		for _, loc := range v.Locations {
			rawURL := loc.URL
			if rawURL == "" {
				continue
			}

			// Parse out optional subdir after "//".
			var targetURL, sub string
			schemeEnd := strings.Index(rawURL, "://")
			searchStart := 0
			if schemeEnd >= 0 {
				searchStart = schemeEnd + 3
			}
			rest := rawURL[searchStart:]
			if idx := strings.Index(rest, "//"); idx >= 0 {
				targetURL = rawURL[:searchStart+idx]
				sub = rest[idx+2:]
			} else {
				targetURL = rawURL
			}

			// Probe reachability with a HEAD request against the actual archive URL.
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				if resp != nil {
					_ = resp.Body.Close()
				}
				continue
			}
			_ = resp.Body.Close()

			return targetURL, sub
		}
	}
	return "", ""
}

// canonicalizePURL parses a PURL with packageurl-go and re-stringifies it so
// that qualifier ordering, namespace casing, and percent-encoding are all
// normalised before map keying.
// Returns the original string unchanged if parsing fails.
func canonicalizePURL(purl string) string {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return purl
	}
	return p.ToString()
}

// downloadAndIndex downloads a tar.gz archive using a two-pass approach to
// safely extract only the files referenced in index.json, and returns a map
// of canonical-PURL -> VEX document bytes.
//
// Two-pass design:
//  1. Stream the archive into a temp file; parse only index.json to learn
//     which files are referenced.
//  2. Seek back to the start; stream again, reading only referenced files,
//     each capped by maxEntryBytes.
//
// Using os.CreateTemp keeps the compressed archive off the heap and allows
// two sequential seeks without holding the whole payload in memory.
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

	// Buffer the compressed archive to a temp file for two-pass reading.
	tmpFile, err := os.CreateTemp("", "vexhub-*.tar.gz")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	written, err := io.Copy(tmpFile, io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return nil, fmt.Errorf("buffering archive to temp file: %w", err)
	}
	if written > maxArchiveBytes {
		return nil, fmt.Errorf("archive exceeds maximum allowed size of %d bytes", maxArchiveBytes)
	}

	// normalizeName strips the leading top-level directory component (e.g. "vexhub-main/")
	// from a tar entry name first, then optionally strips the subdir prefix.
	normalizeName := func(name string) string {
		// Always strip the leading top-level directory component.
		if idx := strings.Index(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		// Then strip the subdir prefix if one was specified in the manifest URL.
		if subdir != "" {
			if after, found := strings.CutPrefix(name, subdir+"/"); found {
				name = after
			} else if after, found := strings.CutPrefix(name, subdir); found {
				name = after
			}
		}
		return name
	}

	// openTar returns a fresh *tar.Reader positioned at the beginning of the archive.
	openTar := func() (*tar.Reader, error) {
		if _, err := tmpFile.Seek(0, 0); err != nil {
			return nil, fmt.Errorf("seeking temp file for pass: %w", err)
		}
		gz, err := gzip.NewReader(tmpFile)
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader: %w", err)
		}
		return tar.NewReader(gz), nil
	}

	// Pass 1: locate and parse index.json.
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

	// Pass 2: read only the referenced files.
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

	// Build canonical-PURL -> VEX doc map; skip unsupported formats.
	// Empty format is treated as openvex (backward-compatible default).
	vexDocs := make(map[string][]byte, len(index.Packages))
	for _, pkg := range index.Packages {
		if pkg.Format != "" && pkg.Format != "openvex" {
			continue
		}
		docData, ok := fileContents[pkg.Location]
		if !ok {
			continue
		}
		vexDocs[canonicalizePURL(pkg.ID)] = docData
	}

	return vexDocs, nil
}

// emitVEXDocuments looks up each PURL in the VEX index and emits matching documents.
// Both the query PURLs and the index keys are canonicalized via packageurl-go
// before comparison so that PURL spelling variants do not cause misses.
// Documents already emitted in a previous batch are deduplicated via v.seen.
// The channel send is wrapped in a select so that context cancellation
// (e.g. graceful shutdown) is respected and the call never hangs.
func (v *vexHubCertifier) emitVEXDocuments(ctx context.Context, purls []string, vexDocs map[string][]byte, docChannel chan<- *processor.Document) ([]*processor.Document, error) {
	var emitted []*processor.Document
	v.seenMu.Lock()
	defer v.seenMu.Unlock()

	for _, purl := range purls {
		if strings.Contains(purl, "pkg:guac") {
			continue
		}

		lookupKey := canonicalizePURL(purl)

		docData, ok := vexDocs[lookupKey]
		if !ok {
			// Try again with version, qualifiers, and subpath stripped.
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

		if _, seen := v.seen[lookupKey]; seen {
			continue
		}
		v.seen[lookupKey] = struct{}{}

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
			select {
			case <-ctx.Done():
				return emitted, ctx.Err()
			case docChannel <- doc:
			}
		}
		emitted = append(emitted, doc)
	}

	return emitted, nil
}
