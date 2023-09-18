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

// Package vuln attestation parser parses the attestation defined by by
// the certifier using the predicate type
// "https://in-toto.io/attestation/vuln/v0.1" Three different types of ingest
// predicates are created.
//
// - IsOccurences are created mapping between any package
// purls found in the subject, and any digests found under those.
//
// - CertifyVulnerabilies are created mapping any package purl found in the
// subject and any vulnerabilites found in the scanner results. The
// vulnerabilites are treated as OSV.
//
// - IsVulnerabilities are created between any found vulnerability in the
// scanner results (OSV) and either a CVE or GHSA vulnerability that is created
// by parsing the OSV ID.
package vuln

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type parser struct {
	packages   []*generated.PkgInputSpec
	vulnData   *generated.ScanMetadataInput
	vulns      []*generated.VulnerabilityInputSpec
	vulnEquals []assembler.VulnEqualIngest
}

var noVulnInput *generated.VulnerabilityInputSpec = &generated.VulnerabilityInputSpec{Type: "noVuln", VulnerabilityID: ""}

// NewVulnCertificationParser initializes the parser
func NewVulnCertificationParser() common.DocumentParser {
	return &parser{}
}

// Parse breaks out the document into the graph components
func (c *parser) Parse(ctx context.Context, doc *processor.Document) error {
	statement, err := parseVulnCertifyPredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	ps, err := parseSubject(statement)
	if err != nil {
		return fmt.Errorf("unable to parse subject of statement: %w", err)
	}
	c.packages = ps
	c.vulnData = parseMetadata(statement)
	vs, ivs, err := parseVulns(ctx, statement)
	if err != nil {
		return fmt.Errorf("unable to parse vulns of statement: %w", err)
	}
	c.vulns = vs
	c.vulnEquals = ivs
	return nil
}

func parseVulnCertifyPredicate(p []byte) (*attestation_vuln.VulnerabilityStatement,
	error) {
	predicate := attestation_vuln.VulnerabilityStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

func parseSubject(s *attestation_vuln.VulnerabilityStatement) ([]*generated.PkgInputSpec, error) {
	var ps []*generated.PkgInputSpec
	for _, sub := range s.StatementHeader.Subject {
		p, err := helpers.PurlToPkg(sub.Name)
		if err != nil {
			return nil, fmt.Errorf("bad purl in statement header: %w", err)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func parseMetadata(s *attestation_vuln.VulnerabilityStatement) *generated.ScanMetadataInput {
	return &generated.ScanMetadataInput{
		TimeScanned:    *s.Predicate.Metadata.ScannedOn,
		DbUri:          s.Predicate.Scanner.Database.Uri,
		DbVersion:      s.Predicate.Scanner.Database.Version,
		ScannerUri:     s.Predicate.Scanner.Uri,
		ScannerVersion: s.Predicate.Scanner.Version,
	}
}

// TODO (pxp928): Remove creation of osv node and just create the vulnerability nodes specified
func parseVulns(ctx context.Context, s *attestation_vuln.VulnerabilityStatement) ([]*generated.VulnerabilityInputSpec,
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
