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

// Package server implements the document upload API, a network accessible
// endpoint that streams a document straight into the ingestor. It exists so a
// client can hand GUAC a document larger than the pubsub message size limit
// without first standing up a blob store.
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	pb "github.com/guacsec/guac/pkg/ingestor/ingestapi"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	defaultMaxDocumentSize      = 256 << 20 // 256 MiB
	defaultMaxConcurrentIngests = 5
	maxMessageSize              = 16 << 20 // 16 MiB
	healthServiceName           = "guacsec.guac.ingestor.schema.DocumentIngestService"
)

type ingestFunc func(ctx context.Context, d *processor.Document) error

type server struct {
	pb.UnimplementedDocumentIngestServiceServer

	ingest     ingestFunc
	maxDocSize int
	// sem holds one token per in-flight ingest.
	sem chan struct{}

	port        int
	tlsCertFile string
	tlsKeyFile  string
}

// ServerOptions configures the document upload API. The ingestion options
// mirror the flags guacingest already passes to ingestor.Ingest.
type ServerOptions struct {
	Port        int
	TLSCertFile string
	TLSKeyFile  string

	GraphqlEndpoint string
	Transport       http.RoundTripper
	CsubClient      csub_client.Client

	ScanForVulns   bool
	ScanForLicense bool
	ScanForEOL     bool
	ScanForDepsDev bool

	MaxDocumentSize      int
	MaxConcurrentIngests int
}

func NewServer(opts ServerOptions) (*server, error) {
	if opts.MaxDocumentSize < 0 {
		return nil, fmt.Errorf("max document size must not be negative, got %d", opts.MaxDocumentSize)
	}
	if opts.MaxConcurrentIngests < 0 {
		return nil, fmt.Errorf("max concurrent ingests must not be negative, got %d", opts.MaxConcurrentIngests)
	}

	maxDocSize := opts.MaxDocumentSize
	if maxDocSize == 0 {
		maxDocSize = defaultMaxDocumentSize
	}
	maxConcurrent := opts.MaxConcurrentIngests
	if maxConcurrent == 0 {
		maxConcurrent = defaultMaxConcurrentIngests
	}

	ingest := func(ctx context.Context, d *processor.Document) error {
		_, err := ingestor.Ingest(
			ctx,
			d,
			opts.GraphqlEndpoint,
			opts.Transport,
			opts.CsubClient,
			opts.ScanForVulns,
			opts.ScanForLicense,
			opts.ScanForEOL,
			opts.ScanForDepsDev,
		)
		return err
	}

	return &server{
		ingest:      ingest,
		maxDocSize:  maxDocSize,
		sem:         make(chan struct{}, maxConcurrent),
		port:        opts.Port,
		tlsCertFile: opts.TLSCertFile,
		tlsKeyFile:  opts.TLSKeyFile,
	}, nil
}

// IngestDocument receives a document as a stream of chunks and ingests it
// synchronously. The first message on the stream must carry the metadata; every
// subsequent message carries a chunk of the body, concatenated in order.
//
// The response is withheld until the document is in the graph, so a client that
// gets SUCCESS can query for the result immediately, and a client that gets an
// error knows the document did not land and can retry.
func (s *server) IngestDocument(stream pb.DocumentIngestService_IngestDocumentServer) error {
	ctx := stream.Context()

	// Acquire the ingest slot before buffering anything.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		return status.Error(codes.ResourceExhausted, "at ingest capacity, retry later")
	}

	metadata, blob, err := s.receive(stream)
	if err != nil {
		return err
	}

	documentRef := events.GetKey(blob)
	// The logger comes from ctxzap rather than logging.FromContext: a gRPC
	// stream context carries only the key the grpc_zap interceptor set, so
	// logging.FromContext would fall back to a no-op logger and discard every
	// line from here and from the processor.
	childLogger := ctxzap.Extract(ctx).Sugar().With(zap.String(logging.DocumentHash, documentRef))

	doc := &processor.Document{
		Blob: blob,
		// The processor sniffs the real type and format, exactly as it does for
		// documents arriving from a collector.
		Type:   processor.DocumentUnknown,
		Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{
			Collector:   metadata.GetCollectorInformation(),
			Source:      metadata.GetSourceInformation(),
			DocumentRef: documentRef,
		},
		ChildLogger: childLogger,
	}

	childLogger.Infof("ingesting uploaded document of %d bytes from %q", len(blob), doc.SourceInformation.Source)
	if err := s.ingest(ctx, doc); err != nil {
		childLogger.Errorf("unable to ingest uploaded document: %v", err)
		return status.Errorf(codes.Internal, "unable to ingest document: %v", err)
	}

	return stream.SendAndClose(&pb.DocumentIngestResponse{
		Status:      pb.Status_SUCCESS,
		DocumentRef: documentRef,
	})
}

// receive drains the stream into metadata and a document body, rejecting
// malformed streams before any ingestion work is attempted.
func (s *server) receive(stream pb.DocumentIngestService_IngestDocumentServer) (*pb.DocumentMetaData, []byte, error) {
	var metadata *pb.DocumentMetaData
	var buf bytes.Buffer

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Returned unwrapped: status.FromError does not see through a
			// wrapped status, so wrapping would turn a client cancellation or
			// deadline into Unknown.
			return nil, nil, err
		}

		switch r := req.GetRequest().(type) {
		case *pb.DocumentIngestRequest_Metadata:
			if metadata != nil {
				return nil, nil, status.Error(codes.InvalidArgument, "metadata must be sent exactly once")
			}
			metadata = r.Metadata
		case *pb.DocumentIngestRequest_Doc:
			if metadata == nil {
				return nil, nil, status.Error(codes.InvalidArgument, "metadata must be the first message on the stream")
			}
			content := r.Doc.GetContent()
			// A zero length chunk adds nothing to the buffer, so the size cap
			// below can never trip on one. Without this a client could hold an
			// ingest slot forever by sending empty chunks and never closing.
			if len(content) == 0 {
				return nil, nil, status.Error(codes.InvalidArgument, "document chunks must not be empty")
			}
			if buf.Len()+len(content) > s.maxDocSize {
				return nil, nil, status.Errorf(codes.ResourceExhausted, "document exceeds the maximum size of %d bytes", s.maxDocSize)
			}
			buf.Write(content)
		default:
			return nil, nil, status.Error(codes.InvalidArgument, "request must carry either metadata or a document chunk")
		}
	}

	if metadata == nil {
		return nil, nil, status.Error(codes.InvalidArgument, "no metadata received")
	}
	if buf.Len() == 0 {
		return nil, nil, status.Error(codes.InvalidArgument, "no document content received")
	}

	return metadata, buf.Bytes(), nil
}

func (s *server) Serve(ctx context.Context) error {
	logger := logging.FromContext(ctx)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("error opening port %d when starting document ingest server: %w", s.port, err)
	}

	opts := []grpc.ServerOption{
		// Without this the per message limit is the 4 MiB default, so a client
		// chunking larger than that gets a transport level ResourceExhausted
		// that reads like the document size rejection.
		grpc.MaxRecvMsgSize(maxMessageSize),
		grpc.StreamInterceptor(
			grpc_middleware.ChainStreamServer(
				grpc_zap.StreamServerInterceptor(logger.Desugar()),
			)),
	}

	if s.tlsCertFile != "" && s.tlsKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(s.tlsCertFile, s.tlsKeyFile)
		if err != nil {
			return fmt.Errorf("error loading credentials from certificate: %s and key %s: %w", s.tlsCertFile, s.tlsKeyFile, err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	gs := grpc.NewServer(opts...)

	pb.RegisterDocumentIngestServiceServer(gs, s)

	// Enable gRPC health checking
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(gs, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(healthServiceName, healthpb.HealthCheckResponse_SERVING)

	// Enable gRPC reflection for tools like grpcurl
	reflection.Register(gs)

	var wg sync.WaitGroup
	var retErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("document ingest server listening at %v", lis.Addr())
		if err := gs.Serve(lis); err != nil {
			retErr = fmt.Errorf("document ingest grpc server error: %w", err)
		}
	}()
	<-ctx.Done()
	healthServer.Shutdown()
	logger.Infof("context cancelled, gracefully shutting down document ingest grpc server")
	done := make(chan bool, 1)
	go func() {
		gs.GracefulStop()
		wg.Wait()
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logger.Warnf("forcibly shutting down document ingest grpc server")
		gs.Stop()
	}
	wg.Wait()
	return retErr
}
