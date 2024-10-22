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

package csubsource

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/client"
	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/logging"
)

type csubDataSources struct {
	c            client.Client
	lastEntries  *datasource.DataSources
	pollDuration time.Duration
}

// NewFileDataSources creates a datasource which gets its data sources
// from a configuration file. This configuration file is in YAML and
// follows the structure outlined in the FileFormat struct. An example
// is as follows:
func NewCsubDatasource(c client.Client, pollDuration time.Duration) (datasource.CollectSource, error) {
	return &csubDataSources{
		c:            c,
		pollDuration: pollDuration,
	}, nil
}

// GetDataSources returns a data source containing targets for the
// collector to collect
func (d *csubDataSources) GetDataSources(ctx context.Context) (*datasource.DataSources, error) {
	entries, err := d.c.GetCollectEntries(ctx, []*pb.CollectEntryFilter{
		{Type: pb.CollectDataType_DATATYPE_OCI, Glob: "*"},
		{Type: pb.CollectDataType_DATATYPE_GIT, Glob: "*"},
		{Type: pb.CollectDataType_DATATYPE_PURL, Glob: "*"},
		{Type: pb.CollectDataType_DATATYPE_GITHUB_RELEASE, Glob: "*"},
		{Type: pb.CollectDataType_DATATYPE_OCI_REGISTRY, Glob: "*"},
	})
	if err != nil {
		return nil, err
	}
	ds := entriesToSources(ctx, entries)

	return ds, nil
}

// DataSourcesUpdate will return a channel which will get an element
// if the CollectSource has new data. Upon update, nil is inserted
// into the channel and non-nil if the channel no longer is able to
// serve updates.
func (d *csubDataSources) DataSourcesUpdate(ctx context.Context) (<-chan error, error) {
	updateChan := make(chan error)
	go func() {
		timer := time.NewTicker(d.pollDuration)
		for {
			timer.Reset(d.pollDuration)
			select {
			case <-timer.C:
				entries, err := d.c.GetCollectEntries(ctx, []*pb.CollectEntryFilter{})
				if err != nil {
					updateChan <- err
					return
				}
				ds := entriesToSources(ctx, entries)
				if reflect.DeepEqual(ds, d.lastEntries) {
					continue
				}

				d.lastEntries = ds
				updateChan <- nil
			case <-ctx.Done():
				err := fmt.Errorf("file watcher ending from context closure")
				updateChan <- err
				return
			}
		}
	}()
	return updateChan, nil
}

func entriesToSources(ctx context.Context, entries []*pb.CollectEntry) *datasource.DataSources {
	d := &datasource.DataSources{}
	for _, e := range entries {
		switch e.Type {
		case pb.CollectDataType_DATATYPE_GIT:
			d.GitDataSources = append(d.GitDataSources, datasource.Source{
				Value: e.Value,
			})
		case pb.CollectDataType_DATATYPE_OCI:
			d.OciDataSources = append(d.OciDataSources, datasource.Source{
				Value: e.Value,
			})
		case pb.CollectDataType_DATATYPE_PURL:
			d.PurlDataSources = append(d.PurlDataSources, datasource.Source{
				Value: e.Value,
			})
		case pb.CollectDataType_DATATYPE_GITHUB_RELEASE:
			d.GithubReleaseDataSources = append(d.GithubReleaseDataSources, datasource.Source{
				Value: e.Value,
			})
		case pb.CollectDataType_DATATYPE_OCI_REGISTRY:
			d.OciRegistryDataSources = append(d.OciRegistryDataSources, datasource.Source{
				Value: e.Value,
			})

		default:
			// unhandled datatype, skip
			logger := logging.FromContext(ctx)
			logger.Infof("got datatype %v unhandled in csubdatasource", e.Type)
		}
	}
	return d
}
