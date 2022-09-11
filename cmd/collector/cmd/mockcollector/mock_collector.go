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

package mockcollector

import (
	"context"
	"fmt"
	"time"

	"github.com/guacsec/guac/internal/testing/ingestor/simpledoc"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func NewMockCollector() *mockCollector {
	return &mockCollector{}
}

type mockCollector struct{}

func (m *mockCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	for i := 0; i < 5; i++ {
		docChannel <- mockDoc(i)
		time.Sleep(5 * time.Second)
	}
	return nil
}

func (m *mockCollector) Type() string {
	return "mock-collector"
}

func mockDoc(i int) *processor.Document {
	return &processor.Document{
		Blob: []byte(fmt.Sprintf(`{
			"issuer": "google-%d.com",
			"info": "this is a cool document",
			"nested": [{
				"issuer": "google.com",
				"info": "this is a cooler nested doc 1"
			},{
				"issuer": "google.com",
				"info": "this is a cooler nested doc 2"
			}]
		   }`, i)),
		Type:              simpledoc.SimpleDocType,
		Format:            processor.FormatJSON,
		SourceInformation: processor.SourceInformation{},
	}
}
