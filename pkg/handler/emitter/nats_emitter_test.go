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
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
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
		Type:   processor.DocumentITE6SLSA,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
)

func TestNatsEmitter_PublishOnEmit(t *testing.T) {
	Emit(&ite6SLSADoc)
}
