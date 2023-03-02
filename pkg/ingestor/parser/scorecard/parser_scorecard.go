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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	sc "github.com/ossf/scorecard/v4/pkg"
)

type scorecardParser struct {
	scorecardPredicates []*model.ScorecardInputSpec
	srcPredicates       []*model.SourceInputSpec
}

// NewSLSAParser initializes the slsaParser
func NewScorecardParser() common.DocumentParser {
	return &scorecardParser{
		scorecardPredicates: []*model.ScorecardInputSpec{},
		srcPredicates:       []*model.SourceInputSpec{},
	}
}

// Parse breaks out the document into the graph components
func (p *scorecardParser) Parse(ctx context.Context, doc *processor.Document) error {

	if doc.Type != processor.DocumentScorecard {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentScorecard, doc.Type)
	}

	switch doc.Format {
	case processor.FormatJSON:
		var scorecard sc.JSONScorecardResultV2
		if err := json.Unmarshal(doc.Blob, &scorecard); err != nil {
			return err
		}
		scPred, srcPred := getPredicates(&scorecard)
		p.scorecardPredicates = append(p.scorecardPredicates, scPred)
		p.srcPredicates = append(p.srcPredicates, srcPred)
		return nil
	}
	return fmt.Errorf("unable to support parsing of Scorecard document format: %v", doc.Format)
}

func (p *scorecardParser) GetPredicates(ctx context.Context) *assembler.PlaceholderStruct {
	var preds []assembler.CertifyScorecardIngest
	for i, scPred := range p.scorecardPredicates {
		preds = append(preds, assembler.CertifyScorecardIngest{
			Scorecard: scPred,
			Source:    p.srcPredicates[i],
		})
	}
	return &assembler.PlaceholderStruct{
		CertifyScorecard: preds,
	}
}

// GetIdentities gets the identity node from the document if they exist
func (p *scorecardParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func metadataId(s *sc.JSONScorecardResultV2) string {
	return fmt.Sprintf("%v:%v", s.Repo.Name, s.Repo.Commit)
}

func getMetadataNode(s *sc.JSONScorecardResultV2) assembler.MetadataNode {
	mnNode := assembler.MetadataNode{
		MetadataType: "scorecard",
		ID:           metadataId(s),
		Details:      map[string]interface{}{},
	}

	for _, c := range s.Checks {
		mnNode.Details[strings.ReplaceAll(c.Name, "-", "_")] = c.Score
	}
	mnNode.Details["repo"] = sourceUri(s.Repo.Name)
	mnNode.Details["commit"] = hashToDigest(s.Repo.Commit)
	mnNode.Details["scorecard_version"] = s.Scorecard.Version
	mnNode.Details["scorecard_commit"] = hashToDigest(s.Scorecard.Commit)
	mnNode.Details["score"] = float64(s.AggregateScore)

	return mnNode
}

func getArtifactNode(s *sc.JSONScorecardResultV2) assembler.ArtifactNode {
	return assembler.ArtifactNode{
		Name:   sourceUri(s.Repo.Name),
		Digest: hashToDigest(s.Repo.Commit),
	}
}

func sourceUri(s string) string {
	return "git+https://" + s
}

func hashToDigest(h string) string {
	switch len(h) {
	case 40:
		return "sha1:" + h
	case 64:
		return "sha256:" + h
	case 128:
		return "sha512:" + h
	}
	return h
}

func (p *scorecardParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func getPredicates(s *sc.JSONScorecardResultV2) (*model.ScorecardInputSpec, *model.SourceInputSpec) {
	var ns, name string
	idx := strings.LastIndex(s.Repo.Name, "/")
	if idx < 0 {
		name = s.Repo.Name
	}

	ns = s.Repo.Name[:idx]
	name = s.Repo.Name[idx+1:]

	srcInput := model.SourceInputSpec{
		// assuming scorecards is only git
		Type:      "git",
		Namespace: ns,
		Name:      name,
		Commit:    &s.Repo.Commit,
	}

	var checks []*model.ScorecardCheckInputSpec
	for _, c := range s.Checks {
		checks = append(checks, &model.ScorecardCheckInputSpec{
			Check: c.Name,
			Score: c.Score,
		})
	}

	scInput := model.ScorecardInputSpec{
		TimeScanned:      s.Date,
		AggregateScore:   (float64)(s.AggregateScore),
		Checks:           checks,
		ScorecardVersion: s.Scorecard.Version,
		ScorecardCommit:  s.Scorecard.Commit,
	}
	return &scInput, &srcInput
}
