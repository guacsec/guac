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

	"github.com/guacsec/guac/pkg/handler/processor"
)

type Certifier interface {
	// CertifyComponent takes a GUAC component and generates processor.documents that are
	// push to the docChannel to be ingested.
	// Note: there is an implicit contract with "QueryComponents" where the compChan type must be the same as
	// the one used by "components"
	CertifyComponent(ctx context.Context, components interface{}, docChannel chan<- *processor.Document) error
}

type QueryComponents interface {
	// GetComponents runs as a goroutine to get the GUAC components that will be certified by the Certifier interface
	// Note: there is an implicit contract with "CertifyComponent" where the components type must be the same as
	// the one used by "compChan"
	GetComponents(ctx context.Context, compChan chan<- interface{}) error
}

// Emitter processes a document
type Emitter func(*processor.Document) error

// ErrHandler processes an error and returns a boolean representing if
// the error was able to be gracefully handled
type ErrHandler func(error) bool

// CertifierType describes the type of the certifier
type CertifierType string

const (
	CertifierOSV       CertifierType = "OSV"
	CertifierScorecard CertifierType = "scorecard"
)
