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

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/guacsec/guac/pkg/handler/processor"
	pb "github.com/guacsec/guac/pkg/ingestor/ingestapi"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// recorder captures the documents an ingest attempt was handed, so tests can
// assert on what the server assembled without standing up a GraphQL backend.
type recorder struct {
	mu   sync.Mutex
	docs []*processor.Document
	err  error
	// block, when non-nil, holds every ingest until it is closed. Used to
	// exercise the concurrency limit.
	block chan struct{}
}

func (r *recorder) ingest(_ context.Context, d *processor.Document) error {
	if r.block != nil {
		<-r.block
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docs = append(r.docs, d)
	return r.err
}

func (r *recorder) documents() []*processor.Document {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*processor.Document(nil), r.docs...)
}

// newTestServer starts s over an in-process listener and returns a connected
// client. Everything is torn down via t.Cleanup.
func newTestServer(t *testing.T, s *server) pb.DocumentIngestServiceClient {
	t.Helper()
	client, _ := newTestServerWithLogs(t, s)
	return client
}

// newTestServerWithLogs is newTestServer plus the captured server side logs. It
// installs the same grpc_zap interceptor that Serve does, so the logger the
// handler pulls off the stream context is wired the way it is in production.
func newTestServerWithLogs(t *testing.T, s *server) (pb.DocumentIngestServiceClient, *observer.ObservedLogs) {
	t.Helper()

	core, logs := observer.New(zapcore.InfoLevel)
	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer(grpc.StreamInterceptor(
		grpc_zap.StreamServerInterceptor(zap.New(core)),
	))
	pb.RegisterDocumentIngestServiceServer(gs, s)

	go func() {
		if err := gs.Serve(lis); err != nil {
			// Serve returns ErrServerStopped on a clean Stop.
			t.Logf("test server stopped: %v", err)
		}
	}()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial test server: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
		gs.Stop()
	})

	return pb.NewDocumentIngestServiceClient(conn), logs
}

// newRecordingServer wires a server around rec with generous limits, which
// individual tests tighten as needed.
func newRecordingServer(t *testing.T, rec *recorder) (*server, pb.DocumentIngestServiceClient) {
	t.Helper()
	s := &server{
		ingest:     rec.ingest,
		maxDocSize: 1024 * 1024,
		sem:        make(chan struct{}, 1),
	}
	return s, newTestServer(t, s)
}

// upload streams metadata followed by content in chunks of chunkSize.
func upload(ctx context.Context, c pb.DocumentIngestServiceClient, collector, source string, content []byte, chunkSize int) (*pb.DocumentIngestResponse, error) {
	stream, err := c.IngestDocument(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&pb.DocumentIngestRequest{
		Request: &pb.DocumentIngestRequest_Metadata{
			Metadata: &pb.DocumentMetaData{
				CollectorInformation: collector,
				SourceInformation:    source,
			},
		},
	}); err != nil {
		return nil, err
	}
	for start := 0; start < len(content); start += chunkSize {
		end := min(start+chunkSize, len(content))
		if err := stream.Send(&pb.DocumentIngestRequest{
			Request: &pb.DocumentIngestRequest_Doc{
				Doc: &pb.Document{Content: content[start:end]},
			},
		}); err != nil {
			return nil, err
		}
	}
	return stream.CloseAndRecv()
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(logging.WithLogger(context.Background()), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// wantCode asserts err carries the expected gRPC status code.
func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %v, got nil", want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("expected code %v, got %v (%v)", want, got, err)
	}
}

func TestIngestDocument_ReassemblesChunkedDocument(t *testing.T) {
	// A body large enough to require many chunks, so a truncation or ordering
	// bug in the server shows up as a content mismatch.
	content := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	rec := &recorder{}
	_, client := newRecordingServer(t, rec)

	resp, err := upload(testContext(t), client, "test-collector", "test-source", content, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetStatus() != pb.Status_SUCCESS {
		t.Errorf("expected status SUCCESS, got %v", resp.GetStatus())
	}
	if resp.GetDocumentRef() == "" {
		t.Error("expected a documentRef in the response")
	}

	docs := rec.documents()
	if len(docs) != 1 {
		t.Fatalf("expected 1 ingested document, got %d", len(docs))
	}
	got := docs[0]
	if !bytes.Equal(got.Blob, content) {
		t.Errorf("blob mismatch: got %d bytes, want %d", len(got.Blob), len(content))
	}
	if got.SourceInformation.Collector != "test-collector" {
		t.Errorf("expected collector %q, got %q", "test-collector", got.SourceInformation.Collector)
	}
	if got.SourceInformation.Source != "test-source" {
		t.Errorf("expected source %q, got %q", "test-source", got.SourceInformation.Source)
	}
	// The processor sniffs type and format, so the server must not guess them.
	if got.Type != processor.DocumentUnknown {
		t.Errorf("expected type %v, got %v", processor.DocumentUnknown, got.Type)
	}
	if got.Format != processor.FormatUnknown {
		t.Errorf("expected format %v, got %v", processor.FormatUnknown, got.Format)
	}
	if got.ChildLogger == nil {
		t.Error("expected a child logger on the document")
	}
}

func TestIngestDocument_DocumentRefIsContentAddressed(t *testing.T) {
	rec := &recorder{}
	_, client := newRecordingServer(t, rec)
	ctx := testContext(t)

	first, err := upload(ctx, client, "c", "s1", []byte("identical bytes"), 8)
	if err != nil {
		t.Fatalf("unexpected error on first upload: %v", err)
	}
	// Same content, different source: the ref keys off content only.
	second, err := upload(ctx, client, "c", "s2", []byte("identical bytes"), 8)
	if err != nil {
		t.Fatalf("unexpected error on second upload: %v", err)
	}
	if first.GetDocumentRef() != second.GetDocumentRef() {
		t.Errorf("expected identical refs for identical content, got %q and %q",
			first.GetDocumentRef(), second.GetDocumentRef())
	}

	different, err := upload(ctx, client, "c", "s1", []byte("other bytes"), 8)
	if err != nil {
		t.Fatalf("unexpected error on third upload: %v", err)
	}
	if different.GetDocumentRef() == first.GetDocumentRef() {
		t.Error("expected a different ref for different content")
	}
}

func TestIngestDocument_RejectsChunksBeforeMetadata(t *testing.T) {
	rec := &recorder{}
	_, client := newRecordingServer(t, rec)

	stream, err := client.IngestDocument(testContext(t))
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	// Send returns nil even when the server has already failed the stream, so
	// the error surfaces from CloseAndRecv.
	_ = stream.Send(&pb.DocumentIngestRequest{
		Request: &pb.DocumentIngestRequest_Doc{Doc: &pb.Document{Content: []byte("orphan")}},
	})
	_, err = stream.CloseAndRecv()
	wantCode(t, err, codes.InvalidArgument)

	if docs := rec.documents(); len(docs) != 0 {
		t.Errorf("expected no ingest attempt, got %d", len(docs))
	}
}

func TestIngestDocument_RejectsRepeatedMetadata(t *testing.T) {
	rec := &recorder{}
	_, client := newRecordingServer(t, rec)

	stream, err := client.IngestDocument(testContext(t))
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	md := &pb.DocumentIngestRequest{
		Request: &pb.DocumentIngestRequest_Metadata{
			Metadata: &pb.DocumentMetaData{CollectorInformation: "c", SourceInformation: "s"},
		},
	}
	_ = stream.Send(md)
	_ = stream.Send(md)
	_, err = stream.CloseAndRecv()
	wantCode(t, err, codes.InvalidArgument)

	if docs := rec.documents(); len(docs) != 0 {
		t.Errorf("expected no ingest attempt, got %d", len(docs))
	}
}

func TestIngestDocument_RejectsEmptyAndMetadataOnlyStreams(t *testing.T) {
	tests := []struct {
		name      string
		sendMeta  bool
		sendEmpty bool
	}{
		{name: "no messages at all"},
		{name: "metadata but no content", sendMeta: true},
		{name: "metadata and a zero length chunk", sendMeta: true, sendEmpty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{}
			_, client := newRecordingServer(t, rec)

			stream, err := client.IngestDocument(testContext(t))
			if err != nil {
				t.Fatalf("failed to open stream: %v", err)
			}
			if tt.sendMeta {
				_ = stream.Send(&pb.DocumentIngestRequest{
					Request: &pb.DocumentIngestRequest_Metadata{
						Metadata: &pb.DocumentMetaData{CollectorInformation: "c", SourceInformation: "s"},
					},
				})
			}
			if tt.sendEmpty {
				_ = stream.Send(&pb.DocumentIngestRequest{
					Request: &pb.DocumentIngestRequest_Doc{Doc: &pb.Document{Content: nil}},
				})
			}
			_, err = stream.CloseAndRecv()
			wantCode(t, err, codes.InvalidArgument)

			if docs := rec.documents(); len(docs) != 0 {
				t.Errorf("expected no ingest attempt, got %d", len(docs))
			}
		})
	}
}

func TestIngestDocument_LogsThroughTheStreamLogger(t *testing.T) {
	rec := &recorder{}
	s := &server{
		ingest:     rec.ingest,
		maxDocSize: 1024,
		sem:        make(chan struct{}, 1),
	}
	client, logs := newTestServerWithLogs(t, s)

	resp, err := upload(testContext(t), client, "c", "s", []byte("a document"), 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A logger pulled off the wrong context key is a no-op logger, which
	// silently swallows every line the handler and the processor emit. Assert
	// on real output rather than on the logger being non-nil, which a no-op
	// logger also satisfies.
	tagged := logs.FilterField(zap.String(logging.DocumentHash, resp.GetDocumentRef())).All()
	if len(tagged) == 0 {
		t.Errorf("expected a log line tagged with %s=%s, got %d untagged entries",
			logging.DocumentHash, resp.GetDocumentRef(), logs.Len())
	}

	docs := rec.documents()
	if len(docs) != 1 {
		t.Fatalf("expected 1 ingested document, got %d", len(docs))
	}
	// The processor and parsers log through this one, so it must be live too.
	if !docs[0].ChildLogger.Desugar().Core().Enabled(zapcore.InfoLevel) {
		t.Error("the document's child logger discards everything at info level")
	}
}

func TestIngestDocument_RejectsEmptyChunksMidStream(t *testing.T) {
	// An empty chunk adds nothing to the buffer, so the size cap alone would
	// never end this stream: the server has to reject the chunk itself, or a
	// client can hold an ingest slot indefinitely.
	rec := &recorder{}
	_, client := newRecordingServer(t, rec)

	stream, err := client.IngestDocument(testContext(t))
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	_ = stream.Send(&pb.DocumentIngestRequest{
		Request: &pb.DocumentIngestRequest_Metadata{
			Metadata: &pb.DocumentMetaData{CollectorInformation: "c", SourceInformation: "s"},
		},
	})
	_ = stream.Send(&pb.DocumentIngestRequest{
		Request: &pb.DocumentIngestRequest_Doc{Doc: &pb.Document{Content: []byte("real content")}},
	})
	// Never closed by the client: only a server side rejection ends this.
	for range 100 {
		if err := stream.Send(&pb.DocumentIngestRequest{
			Request: &pb.DocumentIngestRequest_Doc{Doc: &pb.Document{Content: nil}},
		}); err != nil {
			break
		}
	}

	_, err = stream.CloseAndRecv()
	wantCode(t, err, codes.InvalidArgument)

	if docs := rec.documents(); len(docs) != 0 {
		t.Errorf("expected no ingest attempt, got %d", len(docs))
	}
	// The only ingest slot must be free again, which it can only be if the
	// rejected stream actually returned instead of looping on empty chunks.
	if _, err := upload(testContext(t), client, "c", "s", []byte("follow up"), 4); err != nil {
		t.Errorf("follow up upload failed, so the ingest slot was not released: %v", err)
	}
}

func TestIngestDocument_EnforcesMaxDocumentSize(t *testing.T) {
	rec := &recorder{}
	s := &server{
		ingest:     rec.ingest,
		maxDocSize: 1024,
		sem:        make(chan struct{}, 1),
	}
	client := newTestServer(t, s)

	// One byte over the cap, split so that the cap is crossed mid-stream.
	_, err := upload(testContext(t), client, "c", "s", bytes.Repeat([]byte("x"), 1025), 256)
	wantCode(t, err, codes.ResourceExhausted)

	if docs := rec.documents(); len(docs) != 0 {
		t.Errorf("expected no ingest attempt for an oversized document, got %d", len(docs))
	}

	// Exactly at the cap must still be accepted.
	if _, err := upload(testContext(t), client, "c", "s", bytes.Repeat([]byte("x"), 1024), 256); err != nil {
		t.Errorf("expected a document exactly at the cap to be accepted, got %v", err)
	}
}

func TestIngestDocument_PropagatesIngestFailure(t *testing.T) {
	rec := &recorder{err: errors.New("parser exploded")}
	_, client := newRecordingServer(t, rec)

	_, err := upload(testContext(t), client, "c", "s", []byte("some document"), 4)
	wantCode(t, err, codes.Internal)
}

func TestIngestDocument_LimitsConcurrentIngests(t *testing.T) {
	// A single ingest slot, held open, so the second upload cannot start.
	rec := &recorder{block: make(chan struct{})}
	s := &server{
		ingest:     rec.ingest,
		maxDocSize: 1024,
		sem:        make(chan struct{}, 1),
	}
	client := newTestServer(t, s)
	ctx := testContext(t)

	firstDone := make(chan error, 1)
	go func() {
		_, err := upload(ctx, client, "c", "first", []byte("first document"), 4)
		firstDone <- err
	}()

	// Wait for the first upload to occupy the only slot.
	occupied := false
	for range 100 {
		if len(s.sem) == 1 {
			occupied = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !occupied {
		t.Fatal("first upload never acquired the ingest slot")
	}

	// The second upload must be refused rather than queued indefinitely.
	shortCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	_, err := upload(shortCtx, client, "c", "second", []byte("second document"), 4)
	if err == nil {
		t.Fatal("expected the second upload to be refused while at capacity")
	}
	if code := status.Code(err); code != codes.ResourceExhausted && code != codes.DeadlineExceeded {
		t.Errorf("expected ResourceExhausted or DeadlineExceeded, got %v (%v)", code, err)
	}

	close(rec.block)
	if err := <-firstDone; err != nil {
		t.Errorf("first upload should have succeeded, got %v", err)
	}

	// The slot must be released once the first ingest completes.
	if _, err := upload(ctx, client, "c", "third", []byte("third document"), 4); err != nil {
		t.Errorf("expected the slot to be released, got %v", err)
	}
}

func TestNewServer_Defaults(t *testing.T) {
	s, err := NewServer(ServerOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.maxDocSize != defaultMaxDocumentSize {
		t.Errorf("expected maxDocSize %d, got %d", defaultMaxDocumentSize, s.maxDocSize)
	}
	if cap(s.sem) != defaultMaxConcurrentIngests {
		t.Errorf("expected %d ingest slots, got %d", defaultMaxConcurrentIngests, cap(s.sem))
	}
	if s.ingest == nil {
		t.Error("expected an ingest function to be wired")
	}
}

func TestNewServer_RejectsNegativeLimits(t *testing.T) {
	tests := []ServerOptions{
		{MaxDocumentSize: -1},
		{MaxConcurrentIngests: -1},
	}
	for i, opts := range tests {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			if _, err := NewServer(opts); err == nil {
				t.Error("expected an error for a negative limit")
			}
		})
	}
}
