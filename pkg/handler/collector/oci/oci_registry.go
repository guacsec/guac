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

package oci

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/pkg/errors"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/errs"
)

const (
	OCIRegistryCollector = "OCIRegistryCollector"
)

type ociRegistryCollector struct {
	collectDataSource datasource.CollectSource
	checkedDigest     sync.Map
	poll              bool
	interval          time.Duration
	// rcOpts are the regclient options
	rcOpts []regclient.Opt
}

// NewOCIRegistryCollector initializes the oci registry collector that will collect from all
// repos in the given registry
func NewOCIRegistryCollector(ctx context.Context, collectDataSource datasource.CollectSource, poll bool, interval time.Duration, rcOpts ...regclient.Opt) *ociRegistryCollector {
	if rcOpts == nil {
		rcOpts = getRegClientOptions()
	}
	return &ociRegistryCollector{
		collectDataSource: collectDataSource,
		checkedDigest:     sync.Map{},
		poll:              poll,
		interval:          interval,
		rcOpts:            rcOpts,
	}
}

// RetrieveArtifacts get the artifacts from all repositories in the registry based on polling or one time
func (o *ociRegistryCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if o.poll {
		for {
			if err := o.retrieveRegistryArtifacts(ctx, docChannel); err != nil {
				return fmt.Errorf("failed to retrieve registry artifacts: %w", err)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.interval):
			}
		}
	} else {
		if err := o.retrieveRegistryArtifacts(ctx, docChannel); err != nil {
			return fmt.Errorf("failed to retrieve registry artifacts: %w", err)
		}
	}

	return nil
}

func (o *ociRegistryCollector) retrieveRegistryArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	ds, err := o.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	rc := regclient.New(o.rcOpts...)

	// Process each registry from the data sources
	for _, r := range ds.OciRegistryDataSources {
		registry := r.Value
		// Get list of repositories in the registry
		repos, err := o.listRepositories(ctx, rc, registry)
		if err != nil {
			logger.Errorf("failed to list repositories for registry %s: %v", registry, err)
			continue
		}

		// Create new data source for repositories
		repoSources := make([]datasource.Source, len(repos))
		for i, repo := range repos {
			repoSources[i] = datasource.Source{
				Value: fmt.Sprintf("%s/%s", registry, repo),
			}
		}

		repoDataSource, err := inmemsource.NewInmemDataSources(&datasource.DataSources{
			OciDataSources: repoSources,
		})
		if err != nil {
			return fmt.Errorf("unable to create repository datasource: %w", err)
		}

		// Create OCI collector for repositories
		ociCollector := NewOCICollector(ctx, repoDataSource, false, o.interval, o.rcOpts...)
		if err := ociCollector.RetrieveArtifacts(ctx, docChannel); err != nil {
			logger.Errorf("failed to retrieve artifacts from repository %s: %v", registry, err)
			continue
		}

		// Sync collected digests
		o.syncCollectedDigests(&ociCollector.checkedDigest)
	}

	return nil
}

func (o *ociRegistryCollector) listRepositories(ctx context.Context, rc *regclient.RegClient, registry string) ([]string, error) {
	rl, err := rc.RepoList(ctx, registry)
	if err != nil {
		if errors.Is(err, errs.ErrNotImplemented) {
			return nil, fmt.Errorf("registry %s does not support _catalog API: %w", registry, err)
		}
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}

	if rl == nil || len(rl.Repositories) == 0 {
		return nil, fmt.Errorf("no repositories found in registry %s", registry)
	}

	return rl.Repositories, nil
}

func (o *ociRegistryCollector) syncCollectedDigests(sourceDigests *sync.Map) {
	sourceDigests.Range(func(key, value interface{}) bool {
		if k, ok := key.(string); ok {
			if v, ok := value.([]string); ok {
				o.checkedDigest.Store(k, v)
			}
		}
		return true
	})
}

// Type is the collector type of the collector
func (o *ociRegistryCollector) Type() string {
	return OCIRegistryCollector
}
