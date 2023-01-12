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
	"fmt"
	"net"

	"github.com/nats-io/nats-server/v2/server"
	natsserver "github.com/nats-io/nats-server/v2/test"
)

const (
	TEST_HOST string = "127.0.0.1"
)

type natsTestServer struct {
	server *server.Server
}

func NewNatsTestServer() *natsTestServer {
	return &natsTestServer{}
}

func runServerOnPort(port int) (*server.Server, error) {
	opts := natsserver.DefaultTestOptions
	opts.Host = TEST_HOST
	opts.Port = port
	return runServerWithOptions(&opts), nil
}

func runServerWithOptions(opts *server.Options) *server.Server {
	return natsserver.RunServer(opts)
}

func (n *natsTestServer) EnableJetStreamForTest() (string, error) {
	port, err := getFreePort()
	if err != nil {
		return "", err
	}
	s, err := runServerOnPort(port)
	if err != nil {
		return "", err
	}
	err = s.EnableJetStream(&server.JetStreamConfig{})
	if err != nil {
		s.Shutdown()
		return "", fmt.Errorf("unexpected error initializing test NATS: %v", err)
	}
	n.server = s
	url := fmt.Sprintf("nats://%s:%d", TEST_HOST, port)
	return url, nil
}

func (n *natsTestServer) Shutdown() {
	n.server.Shutdown()
}

// GetFreePort asks the kernel for a free open port that is ready to use.
func getFreePort() (int, error) {
	a, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port, nil
		}
	}
	return 0, err
}
