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
	"crypto/tls"
	"crypto/x509"
	"fmt"

	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

type CsubClientOptions struct {
	Addr          string
	Tls           bool
	TlsSkipVerify bool
}

func ValidateCsubClientFlags(addr string, tls bool, tlsSkipVerify bool) (CsubClientOptions, error) {
	return CsubClientOptions{
		Addr:          addr,
		Tls:           tls,
		TlsSkipVerify: tlsSkipVerify,
	}, nil
}

func NewClient(opts CsubClientOptions) (Client, error) {

	var creds credentials.TransportCredentials
	if !opts.Tls {
		// Set up a connection to the server.
		creds = insecure.NewCredentials()
	} else {
		// Get the system certificates.
		sysPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to get system cert: %w", err)
		}
		// Connect to the service using TLS.
		creds = credentials.NewTLS(&tls.Config{RootCAs: sysPool, InsecureSkipVerify: opts.TlsSkipVerify})
	}

	conn, err := grpc.Dial(opts.Addr, grpc.WithTransportCredentials(creds))
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
