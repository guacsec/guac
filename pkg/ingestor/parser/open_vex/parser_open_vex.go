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

package open_vex

import (
	"context"

	json "github.com/json-iterator/go"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

var (
	justificationsMap = map[string]generated.VexJustification{
		"component_not_present":                             generated.VexJustificationComponentNotPresent,
		"vulnerable_code_not_present":                       generated.VexJustificationVulnerableCodeNotPresent,
		"vulnerable_code_not_in_execute_path":               generated.VexJustificationVulnerableCodeNotInExecutePath,
		"vulnerable_code_cannot_be_controlled_by_adversary": generated.VexJustificationVulnerableCodeCannotBeControlledByAdversary,
		"inline_mitigations_already_exist":                  generated.VexJustificationInlineMitigationsAlreadyExist,
	}

	vexStatusMap = map[string]generated.VexStatus{
		"not_affected":        generated.VexStatusNotAffected,
		"affected":            generated.VexStatusAffected,
		"fixed":               generated.VexStatusFixed,
		"under_investigation": generated.VexStatusUnderInvestigation,
	}
)

type openVEXParser struct {
	identifierStrings *common.IdentifierStrings
	openVex           *vex.VEX
}

func NewOpenVEXParser() common.DocumentParser {
	return &openVEXParser{
		identifierStrings: &common.IdentifierStrings{},
	}
}

// Parse breaks out the document into the graph components
func (c *openVEXParser) Parse(ctx context.Context, doc *processor.Document) error {
	return json.Unmarshal(doc.Blob, &c.openVex)
}

// GetIdentities gets the identity node from the document if they exist
func (c *openVEXParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *openVEXParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return c.identifierStrings, nil
}

func (c *openVEXParser) generateVexIngest(vulnInput *generated.VulnerabilityInputSpec, vexStatement *vex.Statement, status string) ([]assembler.VexIngest, error) {
	var vi []assembler.VexIngest

	for _, p := range vexStatement.Products {
		vd := generated.VexStatementInputSpec{}
		vd.KnownSince = *c.openVex.Metadata.Timestamp
		vd.Origin = c.openVex.Metadata.ID

		ingest := assembler.VexIngest{}

		if vexStatus, ok := vexStatusMap[status]; ok {
			vd.Status = vexStatus
		}

		if vd.Status == generated.VexStatusNotAffected {
			vd.Statement = vexStatement.ImpactStatement
		} else if vd.Status == generated.VexStatusAffected {
			vd.Statement = vexStatement.ActionStatement
		}

		vd.VexJustification = justificationsMap[string(vexStatement.Justification)]

		ingest.VexData = &vd
		ingest.Vulnerability = vulnInput

		var err error
		if ingest.Pkg, err = helpers.PurlToPkg(p); err != nil {
			return nil, err
		}

		c.identifierStrings.PurlStrings = append(c.identifierStrings.PurlStrings, p)

		vi = append(vi, ingest)
	}

	return vi, nil
}

func (c *openVEXParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	logger := logging.FromContext(ctx)

	var vis []assembler.VexIngest
	var cvs []assembler.CertifyVulnIngest

	for _, s := range c.openVex.Statements {
		vuln, err := helpers.CreateVulnInput(s.Vulnerability)
		if err != nil {
			logger.Errorf("failed to create vulnerability input: %v", err)
			continue
		}

		vi, err := c.generateVexIngest(vuln, &s, string(s.Status))
		if err != nil {
			logger.Errorf("failed to generate vex ingest: %v", err)
			continue
		}

		for _, ingest := range vi {
			vis = append(vis, ingest)

			if s.Status == vex.StatusAffected || s.Status == vex.StatusUnderInvestigation {
				vulnData := generated.ScanMetadataInput{
					TimeScanned: *c.openVex.Metadata.Timestamp,
				}
				cv := assembler.CertifyVulnIngest{
					Pkg:           ingest.Pkg,
					Vulnerability: vuln,
					VulnData:      &vulnData,
				}
				cvs = append(cvs, cv)
			}
		}
	}

	return &assembler.IngestPredicates{
		Vex:         vis,
		CertifyVuln: cvs,
	}
}
