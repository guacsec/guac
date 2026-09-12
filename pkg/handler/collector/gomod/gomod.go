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

package gomod

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"
	"github.com/package-url/packageurl-go"
)

const (
	GoModCollector = "gomod"
	// defaultBaseURL is the Go module proxy. The proxy protocol is documented
	// at https://go.dev/ref/mod#module-proxy.
	defaultBaseURL = "https://proxy.golang.org"
)

type goModCollector struct {
	collectDataSource datasource.CollectSource
	client            *http.Client
	baseURL           string
	poll              bool
	interval          time.Duration
	// checked dedupes module@version pairs already fetched across poll cycles.
	checked map[string]bool
}

// NewGoModCollector returns a collector that pulls module metadata from the Go
// module proxy for each golang purl handed over by the data source. For every
// module version it emits the .info (version metadata) and .mod (go.mod) blobs.
// A purl with a version fetches just that version; a purl without one is
// expanded to every version the proxy lists for the module. When poll is set it
// keeps re-reading the data source on interval and picks up modules added later.
func NewGoModCollector(collectDataSource datasource.CollectSource, poll bool, interval time.Duration) *goModCollector {
	return &goModCollector{
		collectDataSource: collectDataSource,
		client:            &http.Client{Transport: version.UATransport},
		baseURL:           defaultBaseURL,
		poll:              poll,
		interval:          interval,
		checked:           map[string]bool{},
	}
}

// RetrieveArtifacts fetches go.mod files for the modules in the data source and
// emits a document per module version. When polling it blocks and re-reads the
// data source until the context is cancelled.
func (c *goModCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if c.poll {
		for {
			if err := c.populateModules(ctx, docChannel); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			case <-time.After(c.interval):
			}
		}
	}
	return c.populateModules(ctx, docChannel)
}

func (c *goModCollector) populateModules(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	ds, err := c.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	for _, src := range ds.PurlDataSources {
		module, ver, err := moduleFromPurl(src.Value)
		if err != nil {
			logger.Warnf("skipping non-golang source %q: %v", src.Value, err)
			continue
		}

		versions := []string{ver}
		if ver == "" {
			versions, err = c.listVersions(ctx, module)
			if err != nil {
				logger.Errorf("failed to list versions for %q: %v", module, err)
				continue
			}
		}

		for _, v := range versions {
			key := module + "@" + v
			if c.checked[key] {
				continue
			}
			c.checked[key] = true

			docs, err := c.fetchVersion(ctx, module, v)
			if err != nil {
				logger.Errorf("failed to fetch module %q: %v", key, err)
				// leave it unchecked so a later poll can retry
				delete(c.checked, key)
				continue
			}
			for _, doc := range docs {
				docChannel <- doc
			}
		}
	}
	return nil
}

// listVersions returns the versions the proxy knows about for a module. The
// @v/list endpoint returns one version per line and may be empty for modules
// that only have pseudo-versions.
func (c *goModCollector) listVersions(ctx context.Context, module string) ([]string, error) {
	target := fmt.Sprintf("%s/%s/@v/list", strings.TrimRight(c.baseURL, "/"), escapePath(module))

	body, err := c.get(ctx, target)
	if err != nil {
		return nil, err
	}

	var versions []string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		if v := strings.TrimSpace(scanner.Text()); v != "" {
			versions = append(versions, v)
		}
	}
	return versions, nil
}

// fetchVersion pulls the .info (version metadata, JSON) and .mod (go.mod file)
// for a single module version and returns a document for each, info first.
func (c *goModCollector) fetchVersion(ctx context.Context, module, ver string) ([]*processor.Document, error) {
	base := fmt.Sprintf("%s/%s/@v/%s", strings.TrimRight(c.baseURL, "/"), escapePath(module), escapePath(ver))

	info, err := c.get(ctx, base+".info")
	if err != nil {
		return nil, err
	}
	mod, err := c.get(ctx, base+".mod")
	if err != nil {
		return nil, err
	}

	return []*processor.Document{
		newDoc(info, processor.FormatJSON, base+".info"),
		newDoc(mod, processor.FormatUnknown, base+".mod"),
	}, nil
}

func newDoc(blob []byte, format processor.FormatType, source string) *processor.Document {
	return &processor.Document{
		Blob:   blob,
		Type:   processor.DocumentGoMod,
		Format: format,
		SourceInformation: processor.SourceInformation{
			Collector:   GoModCollector,
			Source:      source,
			DocumentRef: events.GetDocRef(blob),
		},
	}
}

func (c *goModCollector) get(ctx context.Context, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, target)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return body, nil
}

// moduleFromPurl pulls the module path and version out of a golang purl. It also
// accepts a bare module path (optionally with @version) so callers can hand in
// plain module strings.
func moduleFromPurl(value string) (module, ver string, err error) {
	if !strings.HasPrefix(value, "pkg:") {
		module, ver, _ = strings.Cut(value, "@")
		if module == "" {
			return "", "", fmt.Errorf("empty module path")
		}
		return module, ver, nil
	}

	instance, err := packageurl.FromString(value)
	if err != nil {
		return "", "", fmt.Errorf("invalid purl: %w", err)
	}
	if instance.Type != packageurl.TypeGolang {
		return "", "", fmt.Errorf("purl type %q is not golang", instance.Type)
	}

	module = instance.Name
	if instance.Namespace != "" {
		module = instance.Namespace + "/" + instance.Name
	}
	return module, instance.Version, nil
}

// escapePath applies the proxy's case-encoding: every uppercase letter is
// replaced by "!" followed by its lowercase form, so that case-insensitive file
// systems can't collide two different module paths. See go.dev/ref/mod#goproxy-protocol.
func escapePath(s string) string {
	if strings.ToLower(s) == s {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Type returns the collector type
func (c *goModCollector) Type() string {
	return GoModCollector
}
