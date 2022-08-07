//
// Copyright 2022 The AFF Authors.
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

package verifier

import (
	"crypto"

	"github.com/guacsec/guac/pkg/ingestor/processor"
)

// TODO: Create VerifierProvider so we can support more than Sigstore for verifying signatures

type Verifier interface {
	Verify(i *processor.Document) (map[int]VerifiedKey, error)
}

type VerifiedKey struct {
	Key crypto.PublicKey
	ID  string
}
