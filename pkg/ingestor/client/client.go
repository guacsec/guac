//
// Copyright 2026 The GUAC Authors.
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

// Package client talks to the document upload API exposed by guacingest.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"

	pb "github.com/guacsec/guac/pkg/ingestor/ingestapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// defaultChunkSize keeps each message well inside the default gRPC message size
// limit, so the total document size is bounded by the server rather than by the
// transport.
const defaultChunkSize = 512 * 1024 // 512 KiB

type Client interface {
	// IngestDocument streams a document to the ingestor and blocks until it has
	// been ingested. It returns the content addressed reference the server
	// logged the document under.
	IngestDocument(ctx context.Context, collector, source string, doc io.Reader) (string, error)
	Close()
}

type client struct {
	client    pb.DocumentIngestServiceClient
	conn      *grpc.ClientConn
	chunkSize int
}

type IngestClientOptions struct {
	Addr          string
	Tls           bool
	TlsSkipVerify bool
	// ChunkSize is the size in bytes of each streamed chunk. Zero selects the
	// default.
	ChunkSize int
}

func NewClient(opts IngestClientOptions) (Client, error) {
	if opts.ChunkSize < 0 {
		return nil, fmt.Errorf("chunk size must not be negative, got %d", opts.ChunkSize)
	}
	chunkSize := opts.ChunkSize
	if chunkSize == 0 {
		chunkSize = defaultChunkSize
	}

	var creds credentials.TransportCredentials
	if !opts.Tls {
		creds = insecure.NewCredentials()
	} else {
		sysPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to get system cert: %w", err)
		}
		creds = credentials.NewTLS(&tls.Config{RootCAs: sysPool, InsecureSkipVerify: opts.TlsSkipVerify})
	}

	conn, err := grpc.NewClient(opts.Addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}

	return &client{
		client:    pb.NewDocumentIngestServiceClient(conn),
		conn:      conn,
		chunkSize: chunkSize,
	}, nil
}

func (c *client) Close() {
	_ = c.conn.Close()
}

func (c *client) IngestDocument(ctx context.Context, collector, source string, doc io.Reader) (string, error) {
	// Every return path below must release the RPC. Without this a bail out
	// that neither closes nor completes the stream, such as a read failure on
	// doc, leaves the server blocked in Recv holding an ingest slot for as long
	// as the caller's context lives.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.client.IngestDocument(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to open ingest stream: %w", err)
	}

	if err := stream.Send(&pb.DocumentIngestRequest{
		Request: &pb.DocumentIngestRequest_Metadata{
			Metadata: &pb.DocumentMetaData{
				CollectorInformation: collector,
				SourceInformation:    source,
			},
		},
	}); err != nil {
		return "", fmt.Errorf("failed to send document metadata: %w", err)
	}

	buf := make([]byte, c.chunkSize)
	for {
		n, readErr := doc.Read(buf)
		if n > 0 {
			if err := stream.Send(&pb.DocumentIngestRequest{
				Request: &pb.DocumentIngestRequest_Doc{
					Doc: &pb.Document{Content: buf[:n]},
				},
			}); err != nil {
				// A send failure means the server closed the stream early, so
				// the real reason is on the response.
				if _, recvErr := stream.CloseAndRecv(); recvErr != nil {
					return "", fmt.Errorf("server rejected the document: %w", recvErr)
				}
				return "", fmt.Errorf("failed to send document chunk: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("failed to read document: %w", readErr)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return "", fmt.Errorf("failed to ingest document: %w", err)
	}
	if resp.GetStatus() != pb.Status_SUCCESS {
		return "", fmt.Errorf("document ingest returned status %v", resp.GetStatus())
	}

	return resp.GetDocumentRef(), nil
}
