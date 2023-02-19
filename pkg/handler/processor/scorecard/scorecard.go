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

package scorecard

import (
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
	sc "github.com/ossf/scorecard/v4/pkg"
)

// ScorecardProcessor processes Scorecard documents.
// Currently only supports JSON Scorecard documents
type ScorecardProcessor struct {
}

func (p *ScorecardProcessor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentScorecard {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentScorecard, d.Type)
	}

	switch d.Format {
	case processor.FormatJSON:
		var scorecard sc.JSONScorecardResultV2
		if err := json.Unmarshal(d.Blob, &scorecard); err != nil {
			return err
		}
		fmt.Println(scorecard.Repo.Name, scorecard.Repo.Commit)
		if scorecard.Repo.Name == "" ||
			scorecard.Repo.Commit == "" ||
			len(scorecard.Checks) == 0 {
			return fmt.Errorf("missing required scorecard fields")
		}

		return nil
	}

	return fmt.Errorf("unable to support parsing of Scorecard document format: %v", d.Format)
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (p *ScorecardProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentScorecard {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentScorecard, d.Type)
	}

	// Scorecard doesn't unpack into additional documents at the moment.
	return []*processor.Document{}, nil
}
