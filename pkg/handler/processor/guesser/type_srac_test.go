// Copyright 2026 The GUAC Authors.
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

package guesser

import (
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestSRACTypeGuesser(t *testing.T) {
	g := &sracTypeGuesser{}
	if got := g.GuessDocumentType([]byte(`{"schemaVersion":"0.2-draft","documentId":"demo"}`), processor.FormatJSON); got != processor.DocumentSRAC {
		t.Fatalf("GuessDocumentType() = %q, want %q", got, processor.DocumentSRAC)
	}
	if got := g.GuessDocumentType([]byte(`{"schemaVersion":"0.2-draft"}`), processor.FormatJSON); got != processor.DocumentUnknown {
		t.Fatalf("incomplete document guessed as %q", got)
	}
}
