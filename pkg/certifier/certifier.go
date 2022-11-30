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

package certifier

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type Certifier interface {
	// CertifyComponent takes the type Component and recursively scans each dependency
	// aggregating the results for the top/root level artifact. As attestation documents are generated
	// they are push to the docChannel to be ingested
	CertifyComponent(ctx context.Context, rootComponent *Component, docChannel chan<- *processor.Document) error
}

// Emitter processes a document
type Emitter func(*processor.Document) error

// ErrHandler processes an error and returns a boolean representing if
// the error was able to be gracefully handled
type ErrHandler func(error) bool

// CertfierType describes the type of the certifier
type CertfierType string

const (
	CertifierOSV CertfierType = "OSV"
)

// Component represents the top level package node and its dependencies
type Component struct {
	Package     assembler.PackageNode
	DepPackages []*Component
}
