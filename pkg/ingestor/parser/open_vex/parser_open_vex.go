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
	"fmt"

	json "github.com/json-iterator/go"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

var (
	justificationsMap = map[vex.Justification]generated.VexJustification{
		vex.ComponentNotPresent:                         generated.VexJustificationComponentNotPresent,
		vex.VulnerableCodeNotPresent:                    generated.VexJustificationVulnerableCodeNotPresent,
		vex.VulnerableCodeNotInExecutePath:              generated.VexJustificationVulnerableCodeNotInExecutePath,
		vex.VulnerableCodeCannotBeControlledByAdversary: generated.VexJustificationVulnerableCodeCannotBeControlledByAdversary,
		vex.InlineMitigationsAlreadyExist:               generated.VexJustificationInlineMitigationsAlreadyExist,
	}

	vexStatusMap = map[vex.Status]generated.VexStatus{
		vex.StatusNotAffected:        generated.VexStatusNotAffected,
		vex.StatusAffected:           generated.VexStatusAffected,
		vex.StatusFixed:              generated.VexStatusFixed,
		vex.StatusUnderInvestigation: generated.VexStatusUnderInvestigation,
	}
)

type openVEXParser struct {
	identifierStrings *common.IdentifierStrings
	vis               []assembler.VexIngest
	cvs               []assembler.CertifyVulnIngest
}

func NewOpenVEXParser() common.DocumentParser {
	return &openVEXParser{
		identifierStrings: &common.IdentifierStrings{},
	}
}

// Parse breaks out the document into the graph components
func (c *openVEXParser) Parse(ctx context.Context, doc *processor.Document) error {
	var openVex *vex.VEX
	err := json.Unmarshal(doc.Blob, &openVex)
	if err != nil {
		return fmt.Errorf("failed to unmarshal openVEX document: %w", err)
	}

	for _, s := range openVex.Statements {
		vuln, err := helpers.CreateVulnInput(string(s.Vulnerability.Name))
		if err != nil {
			return fmt.Errorf("failed to create vulnerability input: %w", err)
		}

		vi, err := c.generateVexIngest(vuln, &s, string(s.Status), openVex)
		if err != nil {
			return fmt.Errorf("failed to generate vex ingest: %w", err)
		}

		for _, ingest := range vi {
			c.vis = append(c.vis, ingest)

			if s.Status == vex.StatusAffected || s.Status == vex.StatusUnderInvestigation {
				vulnData := generated.ScanMetadataInput{
					TimeScanned: *openVex.Metadata.Timestamp,
				}
				cv := assembler.CertifyVulnIngest{
					Pkg:           ingest.Pkg,
					Vulnerability: vuln,
					VulnData:      &vulnData,
				}
				c.cvs = append(c.cvs, cv)
			}
		}
	}

	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *openVEXParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *openVEXParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return c.identifierStrings, nil
}

func (c *openVEXParser) generateVexIngest(vulnInput *generated.VulnerabilityInputSpec, vexStatement *vex.Statement, status string, openVex *vex.VEX) ([]assembler.VexIngest, error) {
	var vi []assembler.VexIngest

	for _, p := range vexStatement.Products {
		vd := generated.VexStatementInputSpec{}
		vd.KnownSince = *openVex.Metadata.Timestamp
		vd.Origin = openVex.Metadata.ID

		ingest := assembler.VexIngest{}

		if vexStatus, ok := vexStatusMap[vex.Status(status)]; ok {
			vd.Status = vexStatus
		} else {
			return nil, fmt.Errorf("invalid status for openVEX: %s", status)
		}

		if vd.Status == generated.VexStatusNotAffected {
			vd.Statement = vexStatement.ImpactStatement
		} else if vd.Status == generated.VexStatusAffected {
			vd.Statement = vexStatement.ActionStatement
		}

		if just, ok := justificationsMap[vexStatement.Justification]; ok {
			vd.VexJustification = just
		} else {
			vd.VexJustification = generated.VexJustificationNotProvided
		}

		ingest.VexData = &vd
		ingest.Vulnerability = vulnInput

		var err error
		if ingest.Pkg, err = helpers.PurlToPkg(p.ID); err != nil {
			return nil, err
		}

		c.identifierStrings.PurlStrings = append(c.identifierStrings.PurlStrings, p.ID)

		vi = append(vi, ingest)
	}

	return vi, nil
}

func (c *openVEXParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	return &assembler.IngestPredicates{
		Vex:         c.vis,
		CertifyVuln: c.cvs,
	}
}
