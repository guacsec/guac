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

package inmemsource

import (
	"context"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
)

var _ datasource.CollectSource = (*inmemDataSources)(nil)

type inmemDataSources struct {
	dataSources *datasource.DataSources
	updateChan  chan error
}

// NewInmemDataSources creates an in-memory datasource which initializes based on a
// datasource.
func NewInmemDataSources(dataSources *datasource.DataSources) (*inmemDataSources, error) {
	return &inmemDataSources{
		dataSources: dataSources,
		updateChan:  make(chan error),
	}, nil
}

// GetDataSources returns a data source containing targets for the
// collector to collect
func (d *inmemDataSources) GetDataSources(_ context.Context) (*datasource.DataSources, error) {
	return d.dataSources, nil
}

// DataSourcesUpdate will return a channel which will get an element
// if the CollectSource has new data. Upon update, nil is inserted
// into the channel and non-nil if the channel no longer is able to
// serve updates.
func (d *inmemDataSources) DataSourcesUpdate(ctx context.Context) (<-chan error, error) {
	return d.updateChan, nil
}

// UpdateDataSources updates the in-memory datasource with a new set of dataSources
func (d *inmemDataSources) UpdateDataSources(dataSources *datasource.DataSources) {
	d.dataSources = dataSources
	go func() {
		d.updateChan <- nil
	}()
}
