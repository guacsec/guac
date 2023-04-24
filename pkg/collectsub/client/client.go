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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client interface {
	AddCollectEntries(ctx context.Context, entries []*pb.CollectEntry) error
	GetCollectEntries(ctx context.Context, filters []*pb.CollectEntryFilter) ([]*pb.CollectEntry, error)
	Close()
}

type client struct {
	client pb.ColectSubscriberServiceClient
	conn   *grpc.ClientConn
}

func NewClient(addr string) (Client, error) {
	// Set up a connection to the server.
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	c := pb.NewColectSubscriberServiceClient(conn)

	return &client{
		client: c,
		conn:   conn,
	}, nil
}

func (c *client) Close() {
	c.conn.Close()
}

func (c *client) AddCollectEntries(ctx context.Context, entries []*pb.CollectEntry) error {
	res, err := c.client.AddCollectEntries(ctx, &pb.AddCollectEntriesRequest{
		Entries: entries,
	})
	if err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("add collect entry unsuccessful")
	}
	return nil
}

func (c *client) GetCollectEntries(ctx context.Context, filters []*pb.CollectEntryFilter) ([]*pb.CollectEntry, error) {
	res, err := c.client.GetCollectEntries(ctx, &pb.GetCollectEntriesRequest{
		Filters: filters,
	})
	if err != nil {
		return nil, err
	}

	return res.Entries, nil
}
