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
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/vektah/gqlparser/v2/gqlerror"

	// Import regular postgres driver
	_ "github.com/lib/pq"
)

var Errorf = gqlerror.Errorf

// MaxPageSize is the maximum number of results that will be returned in a single query.
const MaxPageSize = 1000

type EntBackend struct {
	backends.Backend
	client *ent.Client
}

func getBackend(ctx context.Context, args backends.BackendArgs) (backends.Backend, error) {
	config, ok := args.(*BackendOptions)
	if !ok {
		return nil, fmt.Errorf("failed to get ent config from backend args")
	}
	client, err := SetupBackend(ctx, config)
	if err != nil {
		return nil, err
	}
	return GetBackend(client)
}

func GetBackend(client *ent.Client) (backends.Backend, error) {
	if client == nil {
		return nil, fmt.Errorf("invalid args: client is required, got nil")
	}

	be := &EntBackend{}
	err := client.Ping(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to ping db: %w", err)
	}

	be.client = client

	return be, nil
}
