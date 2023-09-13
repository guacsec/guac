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
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/pkg/errors"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types"
	"github.com/regclient/regclient/types/ref"
)

const (
	OCIRegistryCollector = "OCIRegistryCollector"
)

type ociRegistryCollector struct {
	collectDataSource datasource.CollectSource
	checkedDigest     map[string][]string
	registry          string
	poll              bool
	interval          time.Duration
}

func NewOCIRegistryCollector(ctx context.Context, registry string, poll bool, interval time.Duration) *ociRegistryCollector {
	return &ociRegistryCollector{
		checkedDigest: map[string][]string{},
		registry:      registry,
		poll:          poll,
		interval:      interval,
	}
}

func (o *ociRegistryCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	r, err := ref.New(o.registry)
	if err != nil {
		return fmt.Errorf("failed to parse ref %s: %v", r, err)
	}

	rcOpts := getRegClientOptions()
	rc := regclient.New(rcOpts...)
	defer rc.Close(ctx, r)

	rl, err := rc.RepoList(ctx, o.registry)
	if err != nil && errors.Is(err, types.ErrNotImplemented) {
		return fmt.Errorf("registry %s does not support underlying _catalog API: %w", o.registry, err)
	}
	if err != nil {
		return fmt.Errorf("failed to list repositories in registry %s: %w", o.registry, err)
	}
	if len(rl.Repositories) == 0 {
		return fmt.Errorf("no repositories found in registry %s", o.registry)
	}

	sources := []datasource.Source{}
	for _, repo := range rl.Repositories {

		sources = append(sources, datasource.Source{
			Value: o.registry + "/" + repo,
		})
	}
	o.collectDataSource, err = inmemsource.NewInmemDataSources(&datasource.DataSources{
		OciDataSources: sources,
	})
	if err != nil {
		return fmt.Errorf("unable to create datasource: %w", err)
	}
	ociCollector := NewOCICollector(ctx, o.collectDataSource, o.poll, o.interval)
	err = ociCollector.RetrieveArtifacts(ctx, docChannel)
	if err != nil {
		return fmt.Errorf("unable to retrieve artifacts from OCI collector: %w", err)
	}
	o.checkedDigest = ociCollector.checkedDigest
	return nil
}

// Type is the collector type of the collector
func (o *ociRegistryCollector) Type() string {
	return OCIRegistryCollector
}
