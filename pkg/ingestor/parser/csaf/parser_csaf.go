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

var (
	justificationsMap = map[string]generated.VexJustification{
		"component_not_present":                             generated.VexJustificationComponentNotPresent,
		"vulnerable_code_not_present":                       generated.VexJustificationVulnerableCodeNotPresent,
		"vulnerable_code_not_in_execute_path":               generated.VexJustificationVulnerableCodeNotInExecutePath,
		"vulnerable_code_cannot_be_controlled_by_adversary": generated.VexJustificationVulnerableCodeCannotBeControlledByAdversary,
		"inline_mitigations_already_exist":                  generated.VexJustificationInlineMitigationsAlreadyExist,
	}

	vexStatusMap = map[string]generated.VexStatus{
		"known_not_affected":  generated.VexStatusNotAffected,
		"known_affected":      generated.VexStatusAffected,
		"fixed":               generated.VexStatusFixed,
		"first_fixed":         generated.VexStatusFixed,
		"under_investigation": generated.VexStatusUnderInvestigation,
		"first_affected":      generated.VexStatusAffected,
		"last_affected":       generated.VexStatusAffected,
		"recommended":         generated.VexStatusAffected,
	}
)

type csafParser struct {
	doc               *processor.Document
	identifierStrings *common.IdentifierStrings

	csaf *csaf.CSAF
}

type visitedProductRef struct {
	productName string
	productID   string
	name        string
	category    string
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
	return c.identifierStrings, nil
}

// findPurl searches the given CSAF product tree recursively to find the
// purl for the specified product reference.
//
// It recursively calls itself on each child branch of the tree in a
// depth first search manner if the nodes name isn't equal to product_ref.
func findPurl(ctx context.Context, tree csaf.ProductBranch, product_ref string) *string {
	return findPurlSearch(ctx, tree, product_ref, make(map[string]bool))
}

func findPurlSearch(ctx context.Context, tree csaf.ProductBranch, product_ref string, visited map[string]bool) *string {
	if visited[tree.Name] {
		return nil
	}
	visited[tree.Name] = true
	if tree.Name == product_ref {
		purl := tree.Product.IdentificationHelper["purl"]
		return &purl
	}

	for _, b := range tree.Branches {
		purl := findPurlSearch(ctx, b, product_ref, visited)
		if purl != nil {
			return purl
		}
	}

	return nil
}

// findProductRef searches for a product reference string for the given product ID
// by recursively traversing the CSAF product tree.
//
// findProductRefSearch was seperated from findProductRef so that the code can use
// a visited map and avoid infinite recursion.
//
// It returns a pointer to the product reference string if found,
// otherwise nil.
func findProductRef(ctx context.Context, tree csaf.ProductBranch, product_id string) *string {
	return findProductRefSearch(ctx, tree, product_id, make(map[visitedProductRef]bool))
}

// findProductRefSearch recursively searches the product tree for a product
// reference matching the given product ID. It does this with a visited map to
// avoid infinite recursion.
//
// It returns a pointer to the product reference string if found,
// otherwise nil.
func findProductRefSearch(ctx context.Context, tree csaf.ProductBranch, product_id string, visited map[visitedProductRef]bool) *string {
	if visited[visitedProductRef{tree.Product.Name, tree.Product.ID, tree.Name, tree.Category}] {
		return nil
	}
	visited[visitedProductRef{tree.Product.Name, tree.Product.ID, tree.Name, tree.Category}] = true

	for _, r := range tree.Relationships {
		if r.FullProductName.ID == product_id {
			return &r.ProductRef
		}
	}

	for _, b := range tree.Branches {
		pref := findProductRefSearch(ctx, b, product_id, visited)
		if pref != nil {
			return pref
		}
	}
	return nil
}

// findActionStatement searches the given Vulnerability tree to find the action statement
// for the product with the given product_id. If a matching product is found, it returns
// a pointer to the Details string for the Remediation.
// If no matching product is found, it returns nil.
func findActionStatement(tree *csaf.Vulnerability, product_id string) *string {
	for _, r := range tree.Remediations {
		for _, p := range r.ProductIDs {
			if p == product_id {
				return &r.Details
			}
		}
	}
	return nil
}

// findImpactStatement searches the given Vulnerability tree to find the impact statement
// for the product with the given product_id. If a matching product is found, it returns
// a pointer to the Details string for the Threat.
// If no matching product is found, it returns nil.
func findImpactStatement(tree *csaf.Vulnerability, product_id string) *string {
	for _, t := range tree.Threats {
		if t.Category == "impact" {
			for _, p := range t.ProductIDs {
				if p == product_id {
					return &t.Details
				}
			}
		}
	}
	return nil
}

// findPkgSpec finds the package specification for the product with the
// given ID in the CSAF document. It returns a pointer to the package
// specification if found, otherwise an error.
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

// generateVexIngest generates a VEX ingest object from a CSAF vulnerability and other input data.
//
// The function maps CSAF data into a VEX ingest object for adding to the vulnerability graph.
// It then tries to find the package for the product ID to add to ingest.
// If it can't be found, it then returns nil, otherwise it returns a pointer to the VEX ingest object.
func (c *csafParser) generateVexIngest(ctx context.Context, vulnInput *generated.VulnerabilityInputSpec, csafVuln *csaf.Vulnerability, status string, product_id string) *assembler.VexIngest {
	logger := logging.FromContext(ctx)
	vi := &assembler.VexIngest{}

	vd := generated.VexStatementInputSpec{}
	vd.KnownSince = c.csaf.Document.Tracking.CurrentReleaseDate
	vd.Origin = c.csaf.Document.Tracking.ID
	vd.VexJustification = generated.VexJustificationNotProvided

	if vexStatus, ok := vexStatusMap[status]; ok {
		vd.Status = vexStatus
	}

	var statement *string
	if vd.Status == generated.VexStatusNotAffected {
		statement = findImpactStatement(csafVuln, product_id)
	} else {
		statement = findActionStatement(csafVuln, product_id)
	}

	if statement != nil {
		vd.Statement = *statement
	}

	for _, flag := range csafVuln.Flags {
		found := false
		for _, pid := range flag.ProductIDs {
			if pid == product_id {
				found = true
			}
		}
		if found {
			if just, ok := justificationsMap[flag.Label]; ok {
				vd.VexJustification = just
			}
		}
	}

	vi.VexData = &vd
	vi.Vulnerability = vulnInput
	c.identifierStrings.PurlStrings = append(c.identifierStrings.PurlStrings, product_id)

	pkg, err := c.findPkgSpec(ctx, product_id)
	if err != nil {
		logger.Warnf("[csaf] unable to locate package for not-affected product %s", product_id)
		return nil
	}
	vi.Pkg = pkg

	return vi
}

// GetPredicates generates the VEX and CertifyVuln predicates for the CSAF document.
//
// It returns a pointer to an assembler.IngestPredicates struct containing the
// generated VEX and CertifyVuln predicates.
func (c *csafParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	rv := &assembler.IngestPredicates{}
	var vis []assembler.VexIngest
	var cvs []assembler.CertifyVulnIngest

	for _, v := range c.csaf.Vulnerabilities {
		vuln, err := helpers.CreateVulnInput(v.CVE)
		if err != nil {
			return nil
		}

		statuses := []string{"fixed", "known_not_affected", "known_affected", "first_affected", "first_fixed", "last_affected", "recommended", "under_investigation"}
		for _, status := range statuses {
			products := v.ProductStatus[status]
			for _, product := range products {
				vi := c.generateVexIngest(ctx, vuln, &v, status, product)
				if vi == nil {
					continue
				}

				if status == "known_affected" || status == "under_investigation" {
					vulnData := generated.ScanMetadataInput{
						TimeScanned: c.csaf.Document.Tracking.CurrentReleaseDate,
					}
					cv := assembler.CertifyVulnIngest{
						Pkg:           vi.Pkg,
						Vulnerability: vuln,
						VulnData:      &vulnData,
					}
					cvs = append(cvs, cv)
				}
				vis = append(vis, *vi)
			}
		}
	}
	rv.Vex = vis
	rv.CertifyVuln = cvs
	return rv
}
