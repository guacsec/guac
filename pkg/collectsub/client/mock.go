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

package client

import (
	"context"
	"fmt"

	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	"github.com/guacsec/guac/pkg/collectsub/server/db/simpledb"
	db "github.com/guacsec/guac/pkg/collectsub/server/db/types"
)

// MockClient is a simple mock client to simulate being connected to a server
type MockClient struct {
	db db.CollectSubscriberDb
}

func NewMockClient() (Client, error) {
	sdb, err := simpledb.NewSimpleDb()
	if err != nil {
		return nil, fmt.Errorf("unable to create simple db: %w", err)
	}
	return &MockClient{
		db: sdb,
	}, nil
}

func (c *MockClient) Close() {}

func (c *MockClient) AddCollectEntries(ctx context.Context, entries []*pb.CollectEntry) error {
	return c.db.AddCollectEntries(ctx, entries) // nolint:wrapcheck
}

func (c *MockClient) GetCollectEntries(ctx context.Context, filters []*pb.CollectEntryFilter) ([]*pb.CollectEntry, error) {
	return c.db.GetCollectEntries(ctx, filters) // nolint:wrapcheck
}
