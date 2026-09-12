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

package pypi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	PypiCollector = "pypi"
	// defaultBaseURL is the PyPI JSON API. A package's metadata is served at
	// <baseURL>/<name>/json.
	defaultBaseURL = "https://pypi.org/pypi"
)

type pypiCollector struct {
	collectDataSource datasource.CollectSource
	client            *http.Client
	baseURL           string
	poll              bool
	interval          time.Duration
	// checkedNames dedupes packages already fetched across poll cycles.
	checkedNames map[string]bool
}

// NewPypiCollector returns a collector that fetches package metadata from the
// PyPI JSON API for each pypi purl provided by the data source. When poll is
// set it keeps re-reading the data source on interval and picks up newly added
// packages.
func NewPypiCollector(collectDataSource datasource.CollectSource, poll bool, interval time.Duration) *pypiCollector {
	return &pypiCollector{
		collectDataSource: collectDataSource,
		client:            &http.Client{Transport: version.UATransport},
		baseURL:           defaultBaseURL,
		poll:              poll,
		interval:          interval,
		checkedNames:      map[string]bool{},
	}
}

// RetrieveArtifacts fetches PyPI metadata for the packages in the data source
// and emits a document per package. When polling it blocks and re-reads the
// data source until the context is cancelled.
func (p *pypiCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if p.poll {
		for {
			if err := p.populatePackages(ctx, docChannel); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			case <-time.After(p.interval):
			}
		}
	}
	return p.populatePackages(ctx, docChannel)
}

func (p *pypiCollector) populatePackages(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	ds, err := p.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	for _, src := range ds.PurlDataSources {
		name, err := pypiNameFromPurl(src.Value)
		if err != nil {
			logger.Warnf("skipping non-pypi source %q: %v", src.Value, err)
			continue
		}
		if p.checkedNames[name] {
			continue
		}
		p.checkedNames[name] = true

		doc, err := p.fetchPackage(ctx, name)
		if err != nil {
			logger.Errorf("failed to fetch pypi metadata for %q: %v", name, err)
			// leave it unchecked so a later poll can retry
			delete(p.checkedNames, name)
			continue
		}
		docChannel <- doc
	}
	return nil
}

func (p *pypiCollector) fetchPackage(ctx context.Context, name string) (*processor.Document, error) {
	target := fmt.Sprintf("%s/%s/json", strings.TrimRight(p.baseURL, "/"), url.PathEscape(name))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, target)
	}

	blob, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return &processor.Document{
		Blob:   blob,
		Type:   processor.DocumentPyPI,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector:   PypiCollector,
			Source:      target,
			DocumentRef: events.GetDocRef(blob),
		},
	}, nil
}

// pypiNameFromPurl extracts the package name from a pypi purl. It accepts a
// bare name as well so callers can hand in plain package names.
func pypiNameFromPurl(value string) (string, error) {
	if !strings.HasPrefix(value, "pkg:") {
		return value, nil
	}
	instance, err := packageurl.FromString(value)
	if err != nil {
		return "", fmt.Errorf("invalid purl: %w", err)
	}
	if instance.Type != packageurl.TypePyPi {
		return "", fmt.Errorf("purl type %q is not pypi", instance.Type)
	}
	return instance.Name, nil
}

// Type returns the collector type
func (p *pypiCollector) Type() string {
	return PypiCollector
}
