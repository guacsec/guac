package open_vex

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/openvex/go-vex/pkg/vex"
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
	doc               *processor.Document
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
	c.doc = doc
	err := json.Unmarshal(doc.Blob, &c.openVex)
	if err != nil {
		return fmt.Errorf("failed to parse OpenVEX: %w", err)
	}

	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *openVEXParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *openVEXParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (c *openVEXParser) generateVexIngest(vulnInput *generated.VulnerabilityInputSpec, vexStatement *vex.Statement, status string) *assembler.VexIngest {
	vi := &assembler.VexIngest{}

	vd := generated.VexStatementInputSpec{}
	vd.KnownSince = *c.openVex.Metadata.Timestamp
	vd.Origin = c.openVex.Metadata.ID

	if vexStatus, ok := vexStatusMap[status]; ok {
		vd.Status = vexStatus
	}

	if vd.Status == generated.VexStatusNotAffected {
		vd.Statement = vexStatement.ImpactStatement
	} else {
		vd.Statement = vexStatement.ActionStatement
	}

	vd.VexJustification = justificationsMap[string(vexStatement.Justification)]

	vi.VexData = &vd
	vi.Vulnerability = vulnInput

	for _, p := range vexStatement.Products {
		// TODO: Add package information
		// currently there is only one package, but multiple products, need to fix this.

		vi.Pkg, _ = helpers.PurlToPkg(p)
	}

	return vi
}

func (c *openVEXParser) GetPredicates(_ context.Context) *assembler.IngestPredicates {
	rv := &assembler.IngestPredicates{}
	var vis []assembler.VexIngest
	var cvs []assembler.CertifyVulnIngest

	for _, s := range c.openVex.Statements {
		vuln, err := helpers.CreateVulnInput(s.Vulnerability)
		if err != nil {
			return nil
		}

		vi := c.generateVexIngest(vuln, &s, string(s.Status))
		if vi == nil {
			continue
		}
		vis = append(vis, *vi)

		if s.Status == vex.StatusAffected || s.Status == vex.StatusUnderInvestigation {
			vulnData := generated.ScanMetadataInput{
				TimeScanned: *c.openVex.Metadata.Timestamp,
			}
			cv := assembler.CertifyVulnIngest{
				Pkg:           vi.Pkg, // vi.Pkg is currently nil because vi.Pkg doesn't get set
				Vulnerability: vuln,
				VulnData:      &vulnData,
			}
			cvs = append(cvs, cv)
		}
	}

	rv.Vex = vis
	rv.CertifyVuln = cvs

	return rv
}
