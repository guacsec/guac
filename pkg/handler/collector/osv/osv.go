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

package osv

import (
	"context"
	"fmt"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type osvCollector struct {
	collectDataSource datasource.CollectSource
}

func NewOSVCollector(ctx context.Context, collectDataSource datasource.CollectSource) (*osvCollector, error) {
	return &osvCollector{
		collectDataSource: collectDataSource,
	}, nil
}

// RetrieveArtifacts get the metadata from deps.dev based on the purl provided
func (d *osvCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
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
