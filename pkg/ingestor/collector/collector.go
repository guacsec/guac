//
// Copyright 2022 The AFF Authors.
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

package collector

import (
	"context"

	"github.com/guacsec/guac/pkg/config"
	"github.com/guacsec/guac/pkg/ingestor/collector/gcs"
	"github.com/guacsec/guac/pkg/ingestor/collector/oci"
	"github.com/guacsec/guac/pkg/ingestor/collector/pubsub"
	"github.com/guacsec/guac/pkg/ingestor/collector/rekor"
	"github.com/guacsec/guac/pkg/ingestor/processor"
)

type Collector interface {
	// Retrieve the artifacts from the collector
	RetrieveArtifacts(ctx context.Context) ([]*processor.Document, error)
	// Type is the string representation of the backend
	Type() string
	// Indicated when the collector is done
	IsDone() bool
}

// InitializeBackends creates and initializes every configured storage backend.
func InitializeBackends(ctx context.Context, configuredBackends []string, cfg config.Config) (map[string]Collector, error) {
	// TODO: change which backends to initialize

	// Now only initialize and return the configured ones.
	backends := map[string]Collector{}
	for _, backendType := range configuredBackends {
		switch backendType {
		case gcs.CollectorGCS:
			// Need to change how the bucket address is passed in
			gcsBackend, err := gcs.NewStorageBackend(ctx, cfg)
			if err != nil {
				return nil, err
			}
			backends[backendType] = gcsBackend
		case rekor.CollectorRekor:
			// Add for Rekor
		case oci.CollectorOCI:
			// Add for OCI
		case pubsub.CollectorPubSub:
			//Add for PubSub
		}

	}
	return backends, nil
}
