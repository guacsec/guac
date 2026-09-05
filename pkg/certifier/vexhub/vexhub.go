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

	// defaultCacheTTL applies when the manifest omits update_interval or the
	// value it carries cannot be parsed.
	defaultCacheTTL = time.Hour
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

// vexHubCertifier holds the state that has to outlive a single CertifyComponent
// call: the indexed archive and the documents already emitted.
//
// certify.generateDocuments invokes the registered factory once per component
// batch, so a factory that constructs a fresh certifier each time would reset
// this state on every batch and re-download the archive just as often. Callers
// must build one instance and have the factory hand back that same pointer; the
// mutexes below guard the concurrent CertifyComponent calls that sharing implies.
type vexHubCertifier struct {
	httpClient  *http.Client
	manifestURL string

	// cacheMu guards cache, which holds the indexed archive until its TTL
	// (the manifest's update_interval) expires.
	cacheMu sync.RWMutex
	cache   *archiveCache

	// seenMu guards seen, which holds the DocumentRef of every VEX document
	// already pushed downstream.
	seenMu sync.Mutex
	seen   map[string]struct{}
}

// archiveCache is one indexed VEX archive: canonical PURL -> document bytes.
type archiveCache struct {
	vexDocs map[string][]byte
	expiry  time.Time
}

// NewVEXHubCertifier creates a new VEX Hub certifier.
//
// The returned certifier caches the indexed archive and tracks emitted documents
// on itself, so construct it once and reuse it for the lifetime of the process
// rather than building one inside the certify.RegisterCertifier factory.
func NewVEXHubCertifier(manifestURL string) certifier.Certifier {
	if manifestURL == "" {
		manifestURL = DefaultManifestURL
	}
	return &vexHubCertifier{
		httpClient:  &http.Client{Timeout: httpTimeout},
		manifestURL: manifestURL,
		seen:        make(map[string]struct{}),
	}
}

// CertifyComponent fetches VEX documents from the VEX Hub for the given packages.
func (v *vexHubCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
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

	vexDocs, err := v.indexedDocs(ctx)
	if err != nil {
		return err
	}

	if _, err := v.emitVEXDocuments(ctx, purls, vexDocs, docChannel); err != nil {
		return fmt.Errorf("failed to emit VEX documents: %w", err)
	}

	return nil
}

// indexedDocs returns the indexed archive, refreshing it from the hub when the
// cached copy is absent or past its TTL.
func (v *vexHubCertifier) indexedDocs(ctx context.Context) (map[string][]byte, error) {
	v.cacheMu.RLock()
	cache := v.cache
	v.cacheMu.RUnlock()
	if cache != nil && time.Now().Before(cache.expiry) {
		return cache.vexDocs, nil
	}

	manifest, err := fetchManifest(ctx, v.httpClient, v.manifestURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch VEX Hub manifest: %w", err)
	}

	archiveURL, subdir, err := getArchiveURL(ctx, v.httpClient, manifest)
	if err != nil {
		return nil, fmt.Errorf("no usable archive location in VEX Hub manifest %s: %w", v.manifestURL, err)
	}

	vexDocs, err := downloadAndIndex(ctx, v.httpClient, archiveURL, subdir)
	if err != nil {
		return nil, err
	}

	v.cacheMu.Lock()
	v.cache = &archiveCache{vexDocs: vexDocs, expiry: time.Now().Add(cacheTTL(manifest))}
	v.cacheMu.Unlock()

	// Logged on refresh rather than per batch: with the certifier shared across
	// batches this fires once per update_interval.
	logging.FromContext(ctx).Infof("VEX Hub: indexed %d packages from %s", len(vexDocs), archiveURL)

	return vexDocs, nil
}

// cacheTTL reads update_interval off the supported manifest version, falling
// back to defaultCacheTTL when it is absent or unparseable.
func cacheTTL(manifest *Manifest) time.Duration {
	for _, ver := range manifest.Versions {
		if ver.SpecVersion != supportedSpecVersion {
			continue
		}
		if d, err := time.ParseDuration(ver.UpdateInterval); err == nil && d > 0 {
			return d
		}
		break
	}
	return defaultCacheTTL
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
// returning the first URL whose spec_version matches supportedSpecVersion and
// that a HEAD probe does not positively rule out.
//
// The subdirectory is specified after "//" in the URL (per VEX Repo Spec).
// Example: "https://example.com/archive.tar.gz//vexhub-main" -> archiveURL + subdir "vexhub-main"
//
// Versions with unsupported spec_version values are logged and skipped. When no
// location survives, an error is returned rather than an empty URL, so that an
// unreachable or misconfigured hub is distinguishable from a hub that simply has
// nothing to report.
func getArchiveURL(ctx context.Context, client *http.Client, manifest *Manifest) (archiveURL, subdir string, err error) {
	logger := logging.FromContext(ctx)

	probed := 0
	for _, v := range manifest.Versions {
		if v.SpecVersion != supportedSpecVersion {
			logger.Infof("VEX Hub: skipping unsupported spec_version %q (supported: %q)", v.SpecVersion, supportedSpecVersion)
			continue
		}
		for _, loc := range v.Locations {
			if loc.URL == "" {
				continue
			}
			targetURL, sub := splitSubdir(loc.URL)
			probed++
			if reachable(ctx, client, targetURL) {
				return targetURL, sub, nil
			}
		}
	}

	if probed == 0 {
		return "", "", fmt.Errorf("manifest declares no locations for spec_version %s", supportedSpecVersion)
	}
	return "", "", fmt.Errorf("all %d declared location(s) failed the reachability probe", probed)
}

// splitSubdir separates the archive URL from the optional "//"-delimited
// subdirectory the VEX Repo Spec allows after the host.
func splitSubdir(rawURL string) (targetURL, subdir string) {
	searchStart := 0
	if schemeEnd := strings.Index(rawURL, "://"); schemeEnd >= 0 {
		searchStart = schemeEnd + 3
	}
	rest := rawURL[searchStart:]
	idx := strings.Index(rest, "//")
	if idx < 0 {
		return rawURL, ""
	}
	return rawURL[:searchStart+idx], rest[idx+2:]
}

// reachable probes a candidate archive location with HEAD.
//
// The check is deliberately lenient: plenty of object stores and CDNs answer
// 403/405/501 to HEAD while serving the very same URL over GET, so demanding a
// 200 here would discard locations that work fine. Only a transport error or a
// definitive 404/410 rules a location out.
func reachable(ctx context.Context, client *http.Client, url string) bool {
	logger := logging.FromContext(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		logger.Warnf("VEX Hub: skipping malformed location %s: %v", url, err)
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		logger.Warnf("VEX Hub: location %s is unreachable: %v", url, err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		logger.Warnf("VEX Hub: location %s returned %d, skipping", url, resp.StatusCode)
		return false
	}
	return true
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

// archivePrefix reports the archive-internal prefix that turns tar entry names
// into paths relative to the VEX repository root, given the entry expected to
// hold index.json.
//
// Hubs publish archives both with a single top-level wrapper directory (what a
// GitHub tarball produces) and without one, so the prefix is discovered rather
// than assumed. Only a single leading component is accepted, so an unrelated
// index.json nested deeper in the tree cannot hijack the match.
func archivePrefix(entryName, indexPath string) (string, bool) {
	if entryName == indexPath {
		return "", true
	}
	wrapper, found := strings.CutSuffix(entryName, "/"+indexPath)
	if !found || wrapper == "" || strings.Contains(wrapper, "/") {
		return "", false
	}
	return wrapper + "/", true
}

// repoRelativeName strips the discovered wrapper prefix and the manifest subdir
// from a tar entry name, yielding the path as index.json spells it. Entries
// outside the repository root are reported with ok == false.
func repoRelativeName(entryName, prefix, subdir string) (string, bool) {
	name, ok := strings.CutPrefix(entryName, prefix)
	if !ok {
		return "", false
	}
	if sub := strings.Trim(subdir, "/"); sub != "" {
		if name, ok = strings.CutPrefix(name, sub+"/"); !ok {
			return "", false
		}
	}
	return name, true
}

// readEntry reads a single tar entry, refusing anything over maxEntryBytes.
//
// Reading one byte past the limit is what separates "this file is too big" from
// a file that lands exactly on it; a plain io.LimitReader would hand back a
// truncated document that only fails later as a baffling JSON parse error.
func readEntry(r io.Reader, name string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxEntryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	if int64(len(data)) > maxEntryBytes {
		return nil, fmt.Errorf("%s exceeds maximum entry size of %d bytes", name, maxEntryBytes)
	}
	return data, nil
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

	// Locations inside index.json are relative to the repository root, which sits
	// under the manifest's subdir (when it declares one) and under whatever
	// top-level wrapper directory the archive happens to use. Rather than assume
	// a wrapper exists, pass 1 discovers the prefix from wherever index.json
	// actually turns up and pass 2 reuses it verbatim.
	indexPath := "index.json"
	if sub := strings.Trim(subdir, "/"); sub != "" {
		indexPath = sub + "/index.json"
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
	var (
		indexData []byte
		prefix    string
		found     bool
	)
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
		p, ok := archivePrefix(header.Name, indexPath)
		if !ok {
			continue
		}
		if indexData, err = readEntry(tr1, header.Name); err != nil {
			return nil, err
		}
		prefix, found = p, true
		break
	}
	if !found {
		return nil, fmt.Errorf("%s not found in archive", indexPath)
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
		name, ok := repoRelativeName(header.Name, prefix, subdir)
		if !ok || !needed[name] {
			continue
		}
		data, err := readEntry(tr2, header.Name)
		if err != nil {
			return nil, err
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

// emitVEXDocuments looks up each PURL in the VEX index and emits matching
// documents. Both the query PURLs and the index keys are canonicalized via
// packageurl-go before comparison so that PURL spelling variants do not cause
// misses. The channel send is wrapped in a select so that context cancellation
// (e.g. graceful shutdown) is respected and the call never hangs.
func (v *vexHubCertifier) emitVEXDocuments(ctx context.Context, purls []string, vexDocs map[string][]byte, docChannel chan<- *processor.Document) ([]*processor.Document, error) {
	var emitted []*processor.Document

	for _, purl := range purls {
		if strings.Contains(purl, "pkg:guac") {
			continue
		}

		docData, ok := lookupVEXDoc(vexDocs, purl)
		if !ok {
			continue
		}

		// Dedup on the document digest rather than the PURL. Keying on the PURL
		// would permanently suppress a package once seen, so a statement revised
		// upstream would never reach the pipeline again after a cache refresh --
		// defeating the point of polling on update_interval. The digest lets
		// changed content through while still swallowing unchanged repeats.
		docRef := events.GetDocRef(docData)
		if v.markEmitted(docRef) {
			continue
		}

		doc := &processor.Document{
			Blob:   docData,
			Type:   processor.DocumentOpenVEX,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector:   VEXHubCollector,
				Source:      VEXHubCollector,
				DocumentRef: docRef,
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

// lookupVEXDoc resolves a PURL against the index, retrying with version,
// qualifiers and subpath stripped since hubs commonly key on the bare package.
func lookupVEXDoc(vexDocs map[string][]byte, purl string) ([]byte, bool) {
	if docData, ok := vexDocs[canonicalizePURL(purl)]; ok {
		return docData, true
	}
	p, err := packageurl.FromString(purl)
	if err != nil {
		return nil, false
	}
	p.Version = ""
	p.Qualifiers = packageurl.Qualifiers{}
	p.Subpath = ""
	docData, ok := vexDocs[p.ToString()]
	return docData, ok
}

// markEmitted records docRef and reports whether it had already been emitted.
// The lock is scoped to the map access alone so that it is never held across the
// blocking channel send in emitVEXDocuments.
func (v *vexHubCertifier) markEmitted(docRef string) bool {
	v.seenMu.Lock()
	defer v.seenMu.Unlock()
	if _, seen := v.seen[docRef]; seen {
		return true
	}
	v.seen[docRef] = struct{}{}
	return false
}
