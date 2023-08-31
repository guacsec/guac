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

package cdx_vex

import (
	"context"
	"fmt"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/cyclonedx"
	"github.com/guacsec/guac/pkg/logging"
)

var vexStatusMap = map[cdx.ImpactAnalysisState]generated.VexStatus{
	"resolved":     generated.VexStatusFixed,
	"exploitable":  generated.VexStatusAffected,
	"in_triage":    generated.VexStatusUnderInvestigation,
	"not_affected": generated.VexStatusNotAffected,
}

var justificationsMap = map[cdx.ImpactAnalysisJustification]generated.VexJustification{
	"code_not_present":   generated.VexJustificationVulnerableCodeNotPresent,
	"code_not_reachable": generated.VexJustificationVulnerableCodeNotInExecutePath,
}

type cdxVexParser struct {
	doc               *processor.Document
	identifierStrings *common.IdentifierStrings
	cdxBom            *cdx.BOM
}

func NewCdxVexParser() common.DocumentParser {
	return &cdxVexParser{
		identifierStrings: &common.IdentifierStrings{},
	}
}

// Parse breaks out the document into the graph components
func (c *cdxVexParser) Parse(ctx context.Context, doc *processor.Document) error {
	c.doc = doc
	bom, err := cyclonedx.ParseCycloneDXBOM(doc)
	if err != nil {
		return fmt.Errorf("unable to parse cdx-vex document: %w", err)
	}
	c.cdxBom = bom
	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *cdxVexParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *cdxVexParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return c.identifierStrings, nil
}

// Get package name and range versions to create package input spec for the affected packages.
func (c *cdxVexParser) getAffectedPackages(ctx context.Context, vulnInput *generated.VulnerabilityInputSpec, vexData generated.VexStatementInputSpec, affectsObj cdx.Affects) *[]assembler.VexIngest {
	logger := logging.FromContext(ctx)
	var pkgRef string
	// TODO: retrieve purl from metadata if present - https://github.com/guacsec/guac/blob/main/pkg/ingestor/parser/cyclonedx/parser_cyclonedx.go#L76
	if affectsObj.Ref != "" {
		pkgRef = affectsObj.Ref
	} else {
		logger.Warnf("[cdx vex] package reference not found")
		return nil
	}

	// split ref using # as delimiter.
	pkgRefInfo := strings.Split(pkgRef, "#")
	if len(pkgRefInfo) != 2 {
		logger.Warnf("[cdx vex] malformed package reference: %q", affectsObj.Ref)
		return nil
	}
	pkgURL := pkgRefInfo[1]

	// multiple package versions do not exist, resolve to using ref directly.
	if affectsObj.Range == nil {
		pkg, err := helpers.PurlToPkg(pkgURL)
		if err != nil {
			logger.Warnf("[cdx vex] unable to create package input spec: %v", err)
			return nil
		}

		c.identifierStrings.PurlStrings = append(c.identifierStrings.PurlStrings, pkgURL)
		return &[]assembler.VexIngest{{VexData: &vexData, Vulnerability: vulnInput, Pkg: pkg}}
	}

	// split pkgURL using @ as delimiter.
	pkgURLInfo := strings.Split(pkgURL, "@")
	if len(pkgURLInfo) != 2 {
		logger.Warnf("[cdx vex] malformed package url info: %q", pkgURL)
		return nil
	}

	pkgName := pkgURLInfo[0]
	var viList []assembler.VexIngest
	for _, affect := range *affectsObj.Range {
		// TODO: Handle package range versions (see - https://github.com/CycloneDX/bom-examples/blob/master/VEX/CISA-Use-Cases/Case-8/vex.json#L42)
		if affect.Version == "" {
			continue
		}
		vi := &assembler.VexIngest{
			VexData:       &vexData,
			Vulnerability: vulnInput,
		}

		pkg, err := helpers.PurlToPkg(fmt.Sprintf("%s@%s", pkgName, affect.Version))
		if err != nil {
			logger.Warnf("[cdx vex] unable to create package input spec from purl: %v", err)
			return nil
		}
		vi.Pkg = pkg
		viList = append(viList, *vi)
		c.identifierStrings.PurlStrings = append(c.identifierStrings.PurlStrings, pkgURL)
	}

	return &viList
}

func (c *cdxVexParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	layout := "2006-01-02T15:04:05.000Z"
	pred := &assembler.IngestPredicates{}

	var vex []assembler.VexIngest
	var vulnMetadata []assembler.VulnMetadataIngest
	var certifyVuln []assembler.CertifyVulnIngest
	var status generated.VexStatus
	var justification generated.VexJustification
	var publishedTime time.Time

	for _, vulnerability := range *c.cdxBom.Vulnerabilities {
		vuln, err := helpers.CreateVulnInput(vulnerability.ID)
		if err != nil {
			return nil
		}

		if vexStatus, ok := vexStatusMap[vulnerability.Analysis.State]; ok {
			status = vexStatus
		}

		if vexJustification, ok := justificationsMap[vulnerability.Analysis.Justification]; ok {
			justification = vexJustification
		}

		time, err := time.Parse(layout, vulnerability.Published)
		if err == nil {
			publishedTime = time
		}

		vd := generated.VexStatementInputSpec{
			Status:           status,
			VexJustification: justification,
			KnownSince:       publishedTime,
			Statement:        vulnerability.Analysis.Detail,
			StatusNotes:      fmt.Sprintf("%s:%s", string(vulnerability.Analysis.State), string(vulnerability.Analysis.Justification)),
		}

		for _, affect := range *vulnerability.Affects {
			vi := c.getAffectedPackages(ctx, vuln, vd, affect)
			if vi == nil {
				continue
			}
			vex = append(vex, *vi...)

			for _, v := range *vi {
				if status == generated.VexStatusAffected || status == generated.VexStatusUnderInvestigation {
					cv := assembler.CertifyVulnIngest{
						Vulnerability: vuln,
						VulnData: &generated.ScanMetadataInput{
							TimeScanned: publishedTime,
						},
						Pkg: v.Pkg,
					}
					certifyVuln = append(certifyVuln, cv)
				}
			}
		}

		for _, vulnRating := range *vulnerability.Ratings {
			vm := assembler.VulnMetadataIngest{
				Vulnerability: vuln,
				VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
					ScoreType:  generated.VulnerabilityScoreType(vulnRating.Method),
					ScoreValue: *vulnRating.Score,
					Timestamp:  publishedTime,
				},
			}
			vulnMetadata = append(vulnMetadata, vm)
		}
	}

	pred.Vex = vex
	pred.CertifyVuln = certifyVuln
	pred.VulnMetadata = vulnMetadata
	return pred
}
