//
// Copyright 2022 The GUAC Authors.
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

package emitter

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/simpledoc"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/nats-io/nats-server/v2/server"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

var (
	// Taken from: https://slsa.dev/provenance/v0.1#example
	ite6SLSA = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "_", "digest": {"sha256": "5678..."}}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
		  "buildType": "https://example.com/Makefile",
		  "builder": { "id": "mailto:person@example.com" },
		  "invocation": {
			"configSource": {
			  "uri": "https://example.com/example-1.2.3.tar.gz",
			  "digest": {"sha256": "1234..."},
			  "entryPoint": "src:foo",                
			},
			"parameters": {"CFLAGS": "-O3"}           
		  },
		  "materials": [{
			"uri": "https://example.com/example-1.2.3.tar.gz",
			"digest": {"sha256": "1234..."}
		  }]
		}
	}`
	ite6SLSADoc = processor.Document{
		Blob:   []byte(ite6SLSA),
		Type:   simpledoc.SimpleDocType,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
)

const TEST_PORT = 4222

func RunServerOnPort(port int) *server.Server {
	opts := natsserver.DefaultTestOptions
	opts.Port = port
	return RunServerWithOptions(&opts)
}

func RunServerWithOptions(opts *server.Options) *server.Server {
	return natsserver.RunServer(opts)
}

func TestNatsEmitter_PublishOnEmit(t *testing.T) {
	s := RunServerOnPort(TEST_PORT)
	err := s.EnableJetStream(&server.JetStreamConfig{})
	if err != nil {
		t.Fatalf("unexpected error initializing test NATS: %v", err)
	}
	defer s.Shutdown()
	ctx := context.Background()
	config := NewJetStreamConfig(nats.DefaultURL, "", "")
	ctx, err = JetStreamInit(ctx, config)
	if err != nil {
		t.Fatalf("unexpected error initializing jetstream: %v", err)
	}
	err = testPublish(ctx, &ite6SLSADoc)
	if err != nil {
		t.Fatalf("unexpected error on emit: %v", err)
	}
}

func testPublish(ctx context.Context, d *processor.Document) error {
	logger := logging.FromContext(ctx)
	js := FromContext(ctx)
	docByte, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed marshal of document: %w", err)
	}
	_, err = js.Publish(SubjectNameDocCollected, docByte)
	if err != nil {
		return fmt.Errorf("failed to publish document on stream: %w", err)
	}
	logger.Infof("doc published: %+v", d)
	return nil
}
