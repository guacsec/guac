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

// The Vulnerability attestation parser parses the attestation defined by
// by the certifier using the predicate type"https://in-toto.io/attestation/vuln/v0.1"
// Based on the information contained, a package node is generated with just purl and
// digest (if found). This package node is merged into the graph database as it already exists.
//
// An attestation node is generated that contains the information stored in the attestation document.
// The attestation node is linked to the package node via a "attestation" edge type.
//
// Depending on the number of vulnerabilities found, vulnerability nodes are generated that
// contain just the vulnerability ID that can be used to query for more information as needed.
// The vulnerability node is linked to the attestation node via a "vulnerable" edge type.
package certify_vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

const (
	algorithmSHA256 string = "sha256"
	attestationType string = "CERTIFY_VULN"
)

type vulnCertificationParser struct {
	doc         *processor.Document
	packageNode []assembler.PackageNode
	attestation assembler.AttestationNode
	vulns       []assembler.VulnerabilityNode
}

// NewVulnCertificationParser initializes the vulnCertificationParser
func NewVulnCertificationParser() common.DocumentParser {
	return &vulnCertificationParser{
		packageNode: []assembler.PackageNode{},
		attestation: assembler.AttestationNode{},
		vulns:       []assembler.VulnerabilityNode{},
	}
}

// Parse breaks out the document into the graph components
func (c *vulnCertificationParser) Parse(ctx context.Context, doc *processor.Document) error {
	c.doc = doc
	statement, err := parseVulnCertifyPredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	c.getSubject(statement)
	c.getAttestation(doc.Blob, doc.SourceInformation.Source, statement)
	c.getVulns(doc.Blob, doc.SourceInformation.Source, statement)
	return nil
}

func (c *vulnCertificationParser) getSubject(statement *attestation_vuln.VulnerabilityStatement) {
	currentPackage := assembler.PackageNode{}
	for _, sub := range statement.StatementHeader.Subject {
		currentPackage.Purl = sub.Name
		for alg, ds := range sub.Digest {
			currentPackage.Digest = append(currentPackage.Digest, strings.ToLower(alg+":"+strings.Trim(ds, "'")))
		}
		c.packageNode = append(c.packageNode, currentPackage)
	}
}

func (c *vulnCertificationParser) getAttestation(blob []byte, source string, statement *attestation_vuln.VulnerabilityStatement) {
	h := sha256.Sum256(blob)
	attNode := assembler.AttestationNode{
		FilePath:        source,
		Digest:          algorithmSHA256 + ":" + hex.EncodeToString(h[:]),
		AttestationType: attestationType,
		Payload:         map[string]interface{}{},
		NodeData:        *assembler.NewObjectMetadata(c.doc.SourceInformation),
	}
	attNode.Payload["invocation_parameters"] = statement.Predicate.Invocation.Parameters
	attNode.Payload["invocation_uri"] = statement.Predicate.Invocation.Uri
	attNode.Payload["invocation_eventID"] = statement.Predicate.Invocation.EventID
	attNode.Payload["invocation_producerID"] = statement.Predicate.Invocation.ProducerID
	attNode.Payload["scanner_uri"] = statement.Predicate.Scanner.Uri
	attNode.Payload["scanner_version"] = statement.Predicate.Scanner.Version
	attNode.Payload["scanner_db_uri"] = statement.Predicate.Scanner.Database.Uri
	attNode.Payload["scanner_db_version"] = statement.Predicate.Scanner.Database.Version
	attNode.Payload["metadata_scannedOn"] = statement.Predicate.Metadata.ScannedOn.String()
	for i, result := range statement.Predicate.Scanner.Result {
		attNode.Payload["result_vulnerabilityID_"+strconv.Itoa(i)] = result.VulnerabilityId
		attNode.Payload["result_alias_"+strconv.Itoa(i)] = result.Aliases
	}
	c.attestation = attNode
}

func (c *vulnCertificationParser) getVulns(blob []byte, source string, statement *attestation_vuln.VulnerabilityStatement) {
	for _, id := range statement.Predicate.Scanner.Result {
		vulNode := assembler.VulnerabilityNode{
			VulnerabilityID: id.VulnerabilityId,
			NodeData:        *assembler.NewObjectMetadata(c.doc.SourceInformation),
		}
		c.vulns = append(c.vulns, vulNode)
	}
}

func parseVulnCertifyPredicate(p []byte) (*attestation_vuln.VulnerabilityStatement, error) {
	predicate := attestation_vuln.VulnerabilityStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

// CreateNodes creates the GuacNode for the graph inputs
func (c *vulnCertificationParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, pack := range c.packageNode {
		nodes = append(nodes, pack)
	}
	for _, vuln := range c.vulns {
		nodes = append(nodes, vuln)
	}
	nodes = append(nodes, c.attestation)
	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (c *vulnCertificationParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, i := range foundIdentities {
		edges = append(edges, assembler.IdentityForEdge{IdentityNode: i, AttestationNode: c.attestation})
	}
	for _, pack := range c.packageNode {
		edges = append(edges, assembler.AttestationForEdge{AttestationNode: c.attestation, ForPackage: pack})
	}
	for _, vuln := range c.vulns {
		edges = append(edges, assembler.VulnerableEdge{VulnerabilityNode: vuln, AttestationNode: c.attestation})
	}
	return edges
}

// GetIdentities gets the identity node from the document if they exist
func (c *vulnCertificationParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}
