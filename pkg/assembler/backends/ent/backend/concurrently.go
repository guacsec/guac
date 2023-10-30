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

package backend

import (
	"context"
	"os"
	"strconv"

	"github.com/guacsec/guac/pkg/logging"
	"golang.org/x/sync/errgroup"
)

var concurrent chan struct{}

const MaxConcurrentBulkIngestionString string = "MAX_CONCURRENT_BULK_INGESTION"
const defaultMaxConcurrentBulkIngestion int = 50

func init() {
	logger := logging.FromContext(context.Background())
	size := defaultMaxConcurrentBulkIngestion
	maxConcurrentBulkIngestionEnv, found := os.LookupEnv(MaxConcurrentBulkIngestionString)
	if found {
		maxConcurrentBulkIngestion, err := strconv.Atoi(maxConcurrentBulkIngestionEnv)
		if err != nil {
			logger.Warnf("failed to convert %v value %v to integer. Default value %v will be applied", MaxConcurrentBulkIngestionString, maxConcurrentBulkIngestionEnv, defaultMaxConcurrentBulkIngestion)
			size = defaultMaxConcurrentBulkIngestion
		} else {
			size = maxConcurrentBulkIngestion
		}
	}
	concurrent = make(chan struct{}, size)
}

func concurrently(eg *errgroup.Group, fn func() error) {
	eg.Go(func() error {
		concurrent <- struct{}{}
		err := fn()
		<-concurrent
		return err
	})
}
