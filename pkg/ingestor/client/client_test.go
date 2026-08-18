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

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	pb "github.com/guacsec/guac/pkg/ingestor/ingestapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stubService records the stream a client sent, so the client's framing can be
// asserted without depending on the real ingestor.
type stubService struct {
	pb.UnimplementedDocumentIngestServiceServer

	metadata   *pb.DocumentMetaData
	body       bytes.Buffer
	chunkSizes []int
	// metadataWasFirst records whether metadata arrived before any chunk.
	metadataWasFirst bool
	sawChunk         bool

	failWith error
	respond  *pb.DocumentIngestResponse
	// returned, when non-nil, is closed once the handler returns, so a test can
	// tell whether the RPC was released.
	returned chan struct{}
}

func (s *stubService) IngestDocument(stream pb.DocumentIngestService_IngestDocumentServer) error {
	if s.returned != nil {
		defer close(s.returned)
	}
	if s.failWith != nil {
		return s.failWith
	}
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch r := req.GetRequest().(type) {
		case *pb.DocumentIngestRequest_Metadata:
			s.metadata = r.Metadata
			s.metadataWasFirst = !s.sawChunk
		case *pb.DocumentIngestRequest_Doc:
			s.sawChunk = true
			s.chunkSizes = append(s.chunkSizes, len(r.Doc.GetContent()))
			s.body.Write(r.Doc.GetContent())
		}
	}
	resp := s.respond
	if resp == nil {
		resp = &pb.DocumentIngestResponse{Status: pb.Status_SUCCESS, DocumentRef: "sha256:stub"}
	}
	return stream.SendAndClose(resp)
}

// newStubServer serves stub over a loopback listener and returns a client
// pointed at it. Real TCP is used so the client's own dialling code is covered.
func newStubServer(t *testing.T, stub *stubService, chunkSize int) Client {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	gs := grpc.NewServer()
	pb.RegisterDocumentIngestServiceServer(gs, stub)
	go func() {
		if err := gs.Serve(lis); err != nil {
			t.Logf("stub server stopped: %v", err)
		}
	}()

	c, err := NewClient(IngestClientOptions{Addr: lis.Addr().String(), ChunkSize: chunkSize})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	t.Cleanup(func() {
		c.Close()
		gs.Stop()
	})
	return c
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestIngestDocument_StreamsMetadataThenChunkedBody(t *testing.T) {
	// 2500 bytes at a 1000 byte chunk size exercises a trailing partial chunk,
	// where an off-by-one in the send loop would truncate or over-send.
	content := bytes.Repeat([]byte("a"), 2500)
	stub := &stubService{}
	c := newStubServer(t, stub, 1000)

	ref, err := c.IngestDocument(testContext(t), "my-collector", "my-source", bytes.NewReader(content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref != "sha256:stub" {
		t.Errorf("expected the server's documentRef, got %q", ref)
	}
	if !stub.metadataWasFirst {
		t.Error("metadata must be sent before any document chunk")
	}
	if stub.metadata.GetCollectorInformation() != "my-collector" {
		t.Errorf("expected collector %q, got %q", "my-collector", stub.metadata.GetCollectorInformation())
	}
	if stub.metadata.GetSourceInformation() != "my-source" {
		t.Errorf("expected source %q, got %q", "my-source", stub.metadata.GetSourceInformation())
	}
	if !bytes.Equal(stub.body.Bytes(), content) {
		t.Errorf("body mismatch: got %d bytes, want %d", stub.body.Len(), len(content))
	}
	want := []int{1000, 1000, 500}
	if len(stub.chunkSizes) != len(want) {
		t.Fatalf("expected chunks %v, got %v", want, stub.chunkSizes)
	}
	for i, size := range want {
		if stub.chunkSizes[i] != size {
			t.Errorf("chunk %d: expected %d bytes, got %d", i, size, stub.chunkSizes[i])
		}
	}
}

func TestIngestDocument_SurfacesServerError(t *testing.T) {
	stub := &stubService{failWith: status.Error(codes.ResourceExhausted, "at capacity")}
	c := newStubServer(t, stub, 1024)

	_, err := c.IngestDocument(testContext(t), "c", "s", strings.NewReader("some document"))
	if err == nil {
		t.Fatal("expected an error when the server rejects the stream")
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("expected the server's status code to survive, got %v (%v)", status.Code(err), err)
	}
}

func TestIngestDocument_RejectsNonSuccessStatus(t *testing.T) {
	stub := &stubService{respond: &pb.DocumentIngestResponse{Status: pb.Status_FAILED}}
	c := newStubServer(t, stub, 1024)

	if _, err := c.IngestDocument(testContext(t), "c", "s", strings.NewReader("doc")); err == nil {
		t.Fatal("expected an error for a non SUCCESS status")
	}
}

// errReader fails partway through, standing in for a truncated file read.
type errReader struct {
	readsBeforeError int
	err              error
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.readsBeforeError <= 0 {
		return 0, r.err
	}
	r.readsBeforeError--
	p[0] = 'x'
	return 1, nil
}

func TestIngestDocument_PropagatesReadFailure(t *testing.T) {
	stub := &stubService{}
	c := newStubServer(t, stub, 1024)

	readErr := errors.New("disk went away")
	_, err := c.IngestDocument(testContext(t), "c", "s", &errReader{readsBeforeError: 2, err: readErr})
	if !errors.Is(err, readErr) {
		t.Errorf("expected the read error to be wrapped, got %v", err)
	}
}

func TestIngestDocument_ReleasesTheRPCOnReadFailure(t *testing.T) {
	// Bailing out without closing the stream leaves the server blocked in Recv
	// holding an ingest slot, and the server only has a handful of them. The
	// caller's context is deliberately long lived here, which is the normal
	// case for a service, so nothing else would tear the RPC down.
	returned := make(chan struct{})
	stub := &stubService{returned: returned}
	c := newStubServer(t, stub, 1024)

	_, err := c.IngestDocument(context.Background(), "c", "s",
		&errReader{readsBeforeError: 2, err: errors.New("disk went away")})
	if err == nil {
		t.Fatal("expected an error for a failed read")
	}

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the server handler is still blocked in Recv, so the RPC leaked")
	}
}

func TestNewClient_RejectsNegativeChunkSize(t *testing.T) {
	if _, err := NewClient(IngestClientOptions{Addr: "localhost:2783", ChunkSize: -1}); err == nil {
		t.Error("expected an error for a negative chunk size")
	}
}
