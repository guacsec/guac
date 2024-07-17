//
// Copyright 2024 The GUAC Authors.
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

package clearlydefined

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type parser struct {
	packages              []*generated.PkgInputSpec
	sources               []*generated.SourceInputSpec
	collectedCertifyLegal []*generated.CertifyLegalInputSpec
}

// NewLegalCertificationParser initializes the parser
func NewLegalCertificationParser() common.DocumentParser {
	return &parser{}
}

// Parse breaks out the document into the graph components
func (c *parser) Parse(ctx context.Context, doc *processor.Document) error {
	statement, err := parseLegalCertifyPredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	if err := c.parseSubject(statement); err != nil {
		return fmt.Errorf("unable to parse subject of statement: %w", err)
	}
	c.vulnData = parseMetadata(statement)
	vs, ivs, err := parseVulns(ctx, statement)
	if err != nil {
		return fmt.Errorf("unable to parse vulns of statement: %w", err)
	}
	c.vulns = vs
	c.vulnEquals = ivs
	return nil
}

func parseLegalCertifyPredicate(p []byte) (*attestation.ClearlyDefinedStatement, error) {

	predicate := attestation.ClearlyDefinedStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

func (c *parser) parseSubject(s *attestation.ClearlyDefinedStatement) error {
	for _, sub := range s.Statement.Subject {
		p, err := helpers.PurlToPkg(sub.Uri)
		if err != nil {
			src, err := helpers.GuacSrcIdToSourceInput(sub.Uri)
			if err != nil {
				return fmt.Errorf("failed to parse uri: %s to a package or source with error: %w", sub.Uri, err)
			}
			c.sources = append(c.sources, src)
		}
		c.packages = append(c.packages, p)
	}
	return nil
}

func parseMetadata(s *attestation.ClearlyDefinedStatement) *generated.ScanMetadataInput {
	return &generated.ScanMetadataInput{
		TimeScanned:    s.Predicate.Definition.Meta.Updated,
		DbUri:          s.Predicate.Scanner.Database.Uri,
		DbVersion:      s.Predicate.Scanner.Database.Version,
		ScannerUri:     s.Predicate.Scanner.Uri,
		ScannerVersion: s.Predicate.Scanner.Version,
	}
}

// TODO (pxp928): Remove creation of osv node and just create the vulnerability nodes specified
func parseVulns(_ context.Context, s *attestation.ClearlyDefinedStatement) ([]*generated.VulnerabilityInputSpec,
	[]assembler.VulnEqualIngest, error) {
	var vs []*generated.VulnerabilityInputSpec
	var ivs []assembler.VulnEqualIngest
	for _, id := range s.Predicate.Scanner.Result {
		v := &generated.VulnerabilityInputSpec{
			Type:            "osv",
			VulnerabilityID: strings.ToLower(id.VulnerabilityId),
		}
		vs = append(vs, v)
		vuln, err := helpers.CreateVulnInput(id.VulnerabilityId)
		if err != nil {
			return nil, nil, fmt.Errorf("createVulnInput failed with error: %w", err)
		}
		iv := assembler.VulnEqualIngest{
			Vulnerability:      v,
			EqualVulnerability: vuln,
			VulnEqual: &generated.VulnEqualInputSpec{
				Justification: "Decoded OSV data",
			},
		}
		ivs = append(ivs, iv)
	}
	return vs, ivs, nil
}

func (c *parser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	rv := &assembler.IngestPredicates{
		VulnEqual: c.vulnEquals,
	}
	for _, p := range c.packages {
		if len(c.vulns) > 0 {
			for _, v := range c.vulns {
				cv := assembler.CertifyVulnIngest{
					Pkg:           p,
					Vulnerability: v,
					VulnData:      c.vulnData,
				}
				rv.CertifyVuln = append(rv.CertifyVuln, cv)
			}
		} else {
			rv.CertifyVuln = append(rv.CertifyVuln, assembler.CertifyVulnIngest{
				Pkg:           p,
				Vulnerability: noVulnInput,
				VulnData:      c.vulnData,
			})
		}
	}
	return rv
}

// GetIdentities gets the identity node from the document if they exist
func (c *parser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *parser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}
