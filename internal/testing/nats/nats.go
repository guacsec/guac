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

package nats

import (
	"context"
	"fmt"
	"time"

	"github.com/guacsec/guac/pkg/emitter"
	"github.com/nats-io/nats-server/v2/server"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

const TEST_PORT = 4222

type natsTestServer struct {
	server *server.Server
}

func NewNatsTestServer() *natsTestServer {
	return &natsTestServer{}
}

func runServerOnPort(port int) *server.Server {
	opts := natsserver.DefaultTestOptions
	opts.Port = port
	return runServerWithOptions(&opts)
}

func runServerWithOptions(opts *server.Options) *server.Server {
	return natsserver.RunServer(opts)
}

func (n *natsTestServer) EnableJetStreamForTest(ctx context.Context) (context.Context, error) {
	s := runServerOnPort(TEST_PORT)
	err := s.EnableJetStream(&server.JetStreamConfig{})
	if err != nil {
		return nil, fmt.Errorf("unexpected error initializing test NATS: %v", err)
	}
	time.Sleep(time.Second * 5)
	n.server = s
	config := emitter.NewJetStreamConfig(nats.DefaultURL, "", "")
	ctx, err = emitter.JetStreamInit(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unexpected error initializing jetstream: %v", err)
	}
	return ctx, nil
}

func (n *natsTestServer) Shutdown() {
	n.server.Shutdown()
}
