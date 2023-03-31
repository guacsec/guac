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

package csaf

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"

	"github.com/openvex/go-vex/pkg/csaf"
)

type csafParser struct {
	doc               *processor.Document
	identifierStrings *common.IdentifierStrings

	csaf *csaf.CSAF
}

func NewCsafParser() common.DocumentParser {
	return &csafParser{
		identifierStrings: &common.IdentifierStrings{},
	}
}

// Parse breaks out the document into the graph components
func (c *csafParser) Parse(ctx context.Context, doc *processor.Document) error {
	c.doc = doc
	err := json.Unmarshal(doc.Blob, &c.csaf)
	if err != nil {
		return fmt.Errorf("failed to parse CSAF: %w", err)
	}

	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *csafParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *csafParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func findPurl(ctx context.Context, tree csaf.ProductBranch, product_ref string) *string {
	if tree.Name == product_ref {
		purl := tree.Product.IdentificationHelper["purl"]
		return &purl
	}

	for _, b := range tree.Branches {
		purl := findPurl(ctx, b, product_ref)
		if purl != nil {
			return purl
		}
	}

	return nil
}

func findProductRef(ctx context.Context, tree csaf.ProductBranch, product_id string) *string {
	for _, r := range tree.Relationships {
		if r.FullProductName.ID == product_id {
			return &r.ProductRef
		}
	}

	for _, b := range tree.Branches {
		pref := findProductRef(ctx, b, product_id)
		if pref != nil {
			return pref
		}
	}
	return nil
}

func (c *csafParser) findPkgSpec(ctx context.Context, product_id string) (*generated.PkgInputSpec, error) {
	pref := findProductRef(ctx, c.csaf.ProductTree, product_id)
	if pref == nil {
		return nil, fmt.Errorf("unable to locate product reference for id %s", product_id)
	}

	purl := findPurl(ctx, c.csaf.ProductTree, *pref)
	if purl == nil {
		return nil, fmt.Errorf("unable to locate product url for reference %s", *pref)
	}

	return helpers.PurlToPkg(*purl)
}

func (c *csafParser) generateVexIngest(ctx context.Context, cve *generated.CVEInputSpec, ghsa *generated.GHSAInputSpec, status string, product_id string) *assembler.VexIngest {
	logger := logging.FromContext(ctx)
	vi := &assembler.VexIngest{}

	vd := generated.VexStatementInputSpec{}
	vd.KnownSince = c.csaf.Document.Tracking.CurrentReleaseDate
	vd.Origin = c.csaf.Document.Tracking.ID
	vd.Justification = "known_not_affected"

	vi.VexData = &vd
	vi.CVE = cve
	vi.GHSA = ghsa

	pkg, err := c.findPkgSpec(ctx, product_id)
	if err != nil {
		logger.Warnf("[csaf] unable to locate package for not-affected product %s", product_id)
		return nil
	}
	vi.Pkg = pkg

	return vi
}

func (c *csafParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	logger := logging.FromContext(ctx)

	rv := &assembler.IngestPredicates{}
	var vis []assembler.VexIngest
	var cvs []assembler.CertifyVulnIngest

	logger.Infof("[csaf] starting ingestion")
	if len(c.csaf.Vulnerabilities) > 0 {

		for _, v := range c.csaf.Vulnerabilities {
			cve, ghsa, err := helpers.OSVToGHSACVE(v.CVE)
			if err != nil {
				return nil
			}

			statuses := []string{"fixed", "known_not_affected", "known_affected", "first_affected", "first_fixed", "last_affected", "recommended", "under_investigation"}
			for _, status := range statuses {
				products := v.ProductStatus[status]
				if len(products) > 0 {
					for _, product := range products {
						vi := c.generateVexIngest(ctx, cve, ghsa, status, product)
						if vi == nil {
							continue
						}

						if status == "known_affected" || status == "under_investigation" {
							vulnData := generated.VulnerabilityMetaDataInput{
								TimeScanned: c.csaf.Document.Tracking.CurrentReleaseDate,
							}
							cv := assembler.CertifyVulnIngest{
								Pkg:      vi.Pkg,
								CVE:      cve,
								GHSA:     ghsa,
								VulnData: &vulnData,
							}
							cvs = append(cvs, cv)
						}
						vis = append(vis, *vi)
					}
				}
			}
		}
	}
	rv.Vex = vis
	rv.CertifyVuln = cvs
	return rv
}
