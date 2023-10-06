//
// Copyright 2023 The GUAC Authors.
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

package deps_dev

import (
	"fmt"

	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"github.com/guacsec/guac/pkg/handler/processor"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type DepsDev struct {
}

// ValidateSchema ensures that the document blob can be parsed into a valid data structure
func (d *DepsDev) ValidateSchema(i *processor.Document) error {
	if i.Type != processor.DocumentDepsDev {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentDepsDev, i.Type)
	}

	_, err := parseDepsDev(i.Blob)

	return err
}

// Unpack takes in the document and tries to unpack
func (d *DepsDev) Unpack(i *processor.Document) ([]*processor.Document, error) {
	if i.Type != processor.DocumentDepsDev {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentDepsDev, i.Type)
	}

	// deps.dev doesn't unpack into additional documents at the moment.
	return []*processor.Document{}, nil
}

func parseDepsDev(p []byte) (*deps_dev.PackageComponent, error) {
	packageComponent := deps_dev.PackageComponent{}
	if err := json.Unmarshal(p, &packageComponent); err != nil {
		return nil, err
	}
	return &packageComponent, nil
}
