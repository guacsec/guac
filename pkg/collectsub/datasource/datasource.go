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

package datasource

// CollectSource provides a way for collector to get collect targets from
// a data source (e.g. a file, a database, a pubsub queue, etc.)
//
// This provides the flexibility for collectors to be configured in a
// similar way to prevent configuration drift among collectors, and
// provide a way to centrally manage collector source targets.
type CollectSource interface {
	// GetDataSource returns a data source containing targets for the
	// collector to collect
	GetDataSource() (*DataSource, error)

	// DataSourceUpdate will return a channel which will get an element
	// if the CollectSource has new data
	DataSourceUpdate() <-chan error
}

type DataSource struct {
	OciDataSource  []Source
	GitDataSource  []Source
	PurlDataSource []Source
}

type Source struct {
	Value string
}
