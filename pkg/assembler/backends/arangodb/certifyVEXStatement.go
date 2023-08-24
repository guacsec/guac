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

package arangodb

import (
	"context"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	statusStr           string = "status"
	vexJustificationStr string = "vexJustification"
	statementStr        string = "statement"
	statusNotesStr      string = "statusNotes"
	knownSinceStr       string = "knownSince"
)

func (c *arangoClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	panic(fmt.Errorf("not implemented: CertifyVEXStatement - CertifyVEXStatement"))
}

func getVEXStatementQueryValues(pkg *model.PkgInputSpec, artifact *model.ArtifactInputSpec, vulnerability *model.VulnerabilityInputSpec, vexStatement *model.VexStatementInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	if pkg != nil {
		pkgId := guacPkgId(*pkg)
		values["pkgVersionGuacKey"] = pkgId.VersionId
	} else {
		values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
		values["art_digest"] = strings.ToLower(artifact.Digest)
	}
	if vulnerability != nil {
		vuln := guacVulnId(*vulnerability)
		values["guacVulnKey"] = vuln.VulnerabilityID
	}
	values[statusStr] = vexStatement.Status
	values[vexJustificationStr] = vexStatement.VexJustification
	values[statementStr] = vexStatement.Statement
	values[statusNotesStr] = vexStatement.StatusNotes
	values[knownSinceStr] = vexStatement.KnownSince
	values[origin] = vexStatement.Origin
	values[collector] = vexStatement.Collector

	return values
}

func (c *arangoClient) IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.VulnerabilityInputSpec, vexStatements []*model.VexStatementInputSpec) ([]string, error) {
	return []string{}, fmt.Errorf("not implemented - IngestVEXStatements")
}

func (c *arangoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInputSpec, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	panic(fmt.Errorf("not implemented: IngestVEXStatement - IngestVEXStatement"))
}
