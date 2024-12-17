//
// Copyright 2023 The GUAC Authors.
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

package deps_dev

import (
	"context"
	"fmt"
	"time"

	ddc "github.com/guacsec/guac/internal/client/depsdevclient"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"

	pb "deps.dev/api/v3"

	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	DepsCollector               = "deps.dev"
	goUpperCase                 = "GO"
	golang                      = "golang"
	maven                       = "maven"
	sourceRepo                  = "SOURCE_REPO"
	GetProjectDurationHistogram = "http_deps_dev_project_duration"
	GetVersionErrorsCounter     = "http_deps_dev_version_errors"
	prometheusPrefix            = "deps_dev"
	// RPS = rate per second
	rateLimit = 150
)

type IsDepPackage struct {
	CurrentPackageInput *model.PkgInputSpec
	DepPackageInput     *model.PkgInputSpec
	IsDependency        *model.IsDependencyInputSpec
}

type depsCollector struct {
	dc                   *ddc.DepsClient
	collectDataSource    datasource.CollectSource
	client               pb.InsightsClient
	poll                 bool
	retrieveDependencies bool
	interval             time.Duration
	// add artificial latency to throttle the pagination query
	addedLatency *time.Duration
	checkedPurls map[string]bool
}

func NewDepsCollector(ctx context.Context, collectDataSource datasource.CollectSource, poll, retrieveDependencies bool, interval time.Duration, addedLatency *time.Duration) (*depsCollector, error) {
	ctx = metrics.WithMetrics(ctx, prometheusPrefix)

	dc, err := ddc.NewDepsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize depsdev guac client: %w", err)
	}

	return &depsCollector{
		dc:                   dc,
		collectDataSource:    collectDataSource,
		poll:                 poll,
		retrieveDependencies: retrieveDependencies,
		interval:             interval,
		addedLatency:         addedLatency,
		checkedPurls:         map[string]bool{},
	}, nil
}

// RetrieveArtifacts get the metadata from deps.dev based on the purl provided
func (d *depsCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if d.poll {
		for {
			if err := d.populatePurls(ctx, docChannel); err != nil {
				return fmt.Errorf("unable to retrieve purls from collector subscriber: %w", err)
			}
			select {
			// If the context has been canceled it contains an err which we can throw.
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			case <-time.After(d.interval):
			}
		}
	} else {
		if err := d.populatePurls(ctx, docChannel); err != nil {
			return fmt.Errorf("unable to retrieve purls from collector subscriber: %w", err)
		}
	}
	return nil
}

func (d *depsCollector) populatePurls(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	// TODO(lumb): Populate checkedPurls
	ds, err := d.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	// filter based on checked purls
	purlStrings := []string{}
	purlStrings = append(purlStrings, dsToStr(ds.PurlDataSources)...)

	if !d.retrieveDependencies {
		// Retrieve versions and projects for all purls concurrently
		d.dc.RetrieveVersionsAndProjects(ctx, purlStrings)
		for _, purl := range purlStrings {
			if d.checkedPurls[purl] {
				continue
			}
			d.checkedPurls[purl] = true

			components, err := d.dc.GetMetadata(ctx, purlStrings)
			if err != nil {
				logger.Errorf("Error collecting depsdev metadata: %s", err)
				return err
			}
			emitComponents(ctx, components, docChannel)
		}
		return nil
	}

	if err := d.dc.RetrieveDependencies(ctx, purlStrings); err != nil {
		return fmt.Errorf("failed to get all dependencies: %w", err)
	}
	for _, purl := range purlStrings {
		if d.checkedPurls[purl] {
			continue
		}
		d.checkedPurls[purl] = true

		components, err := d.dc.GetDependencies(ctx, []string{purl})
		if err != nil {
			return fmt.Errorf("failed to fetch dependencies: %w", err)
		}

		emitComponents(ctx, components, docChannel)

		// add artificial latency to throttle the pagination query
		if d.addedLatency != nil {
			time.Sleep(*d.addedLatency)
		}
	}
	return nil
}

func emitComponents(ctx context.Context, components []*ddc.PackageComponent, docChannel chan<- *processor.Document) {
	logger := logging.FromContext(ctx)
	for _, component := range components {
		blob, err := json.Marshal(component)
		if err != nil {
			logger.Errorf("unable to marshal component in deps.dev collector: %s", err)
			continue
		}

		doc := &processor.Document{
			Blob:   blob,
			Type:   processor.DocumentDepsDev,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector:   DepsCollector,
				Source:      DepsCollector,
				DocumentRef: events.GetDocRef(blob),
			},
		}
		docChannel <- doc
	}
}

// Type returns the collector type
func (d *depsCollector) Type() string {
	return DepsCollector
}

// DeregisterCollector deregisters the collector
func (d *depsCollector) DeregisterCollector(collectorType string) error {
	// The DeregisterCollector is a placeholder for removing the metrics from the collector.
	// This is also placeholder for removing state from the collector reference.
	return nil
}

func dsToStr(sources []datasource.Source) []string {
	strList := make([]string, len(sources))
	for i, s := range sources {
		strList[i] = s.Value
	}
	return strList
}
