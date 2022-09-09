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
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/nats-io/nats.go"
)

const (
	GUACSubject string = "GUAC"
)

var (
	nc *nats.Conn
)

func init() {
	initConnection()
}

func initConnection() {
	if nc == nil || !nc.IsConnected() {
		var err error
		nc, err = nats.Connect(nats.DefaultURL)

		if err != nil {
			panic("Unable to connect to nats server")
		}
	}
}

func Emit(d *processor.Document) {
	initConnection()
	// do I need to publish the whole document?
	nc.Publish(GUACSubject, d.Blob)
}

func Register(f func(m *nats.Msg)) {
	initConnection()
	nc.Subscribe(GUACSubject, f)
}
