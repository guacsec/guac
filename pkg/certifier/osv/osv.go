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

package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/certifier"
	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv/internal/osv_query"
	"github.com/guacsec/guac/pkg/handler/processor"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	osv_scanner "golang.org/x/vuln/osv"
)

const (
	URI         string = "osv.dev"
	VERSION     string = "0.0.14"
	INVOC_URI   string = "guac"
	PRODUCER_ID string = "guacsec/guac"
)

var ErrOSVComponenetTypeMismatch error = fmt.Errorf("rootComponent type is not *certifier.Component")

type osvCertifier struct {
	rootComponents *root_package.PackageComponent
}

// NewOSVCertificationParser initializes the OSVCertifier
func NewOSVCertificationParser() certifier.Certifier {
	return &osvCertifier{}
}

// CertifyComponent takes in the root component from the gauc database and does a recursive scan
// to generate vulnerability attestations
func (o *osvCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	if component, ok := rootComponent.(*root_package.PackageComponent); ok {
		o.rootComponents = component
	} else {
		return ErrOSVComponenetTypeMismatch
	}
	m := make(map[string]bool)
	_, err := o.certifyHelper(ctx, o.rootComponents, docChannel, m)
	if err != nil {
		return err
	}
	return nil
}

// certifyHelper recursively checks each component for dependencies.
// If it has dependencies, certifyHelper is re-called until no more dependencies are found.
// The dependency node is appended to the package node array and sent to be queried by OSV
// Once the vulnerabilities are found, an attestation is generated for that package node
// All the vulnerabilities for each dependent package node are collected and the parent package node's
// attestation is generated containing all the vulnerabilities of its dependencies
// these vulnerabilities are passed up until it reaches the root level node which contains an attestation
// with all the aggregate vulnerabilities. The visited map is used to prevent infinite recursion.
func (o *osvCertifier) certifyHelper(ctx context.Context, topLevel *root_package.PackageComponent, docChannel chan<- *processor.Document,
	visited map[string]bool) ([]osv_scanner.Entry, error) {
	if visited == nil {
		return nil, fmt.Errorf("visited map is nil")
	}
	packNodes := []assembler.PackageNode{}
	totalDepVul := []osv_scanner.Entry{}
	if visited[topLevel.Package.Purl] {
		return nil, nil
	}
	visited[topLevel.Package.Purl] = true
	for _, depPack := range topLevel.DepPackages {
		if len(depPack.DepPackages) > 0 {
			depVulns, err := o.certifyHelper(ctx, depPack, docChannel, visited)
			if err != nil {
				return nil, err
			}
			if depVulns != nil {
				totalDepVul = append(totalDepVul, depVulns...)
			}
		} else {
			packNodes = append(packNodes, depPack.Package)
		}
	}

	i := 0
	for i < len(packNodes) {
		query, lastIndex := getQuery(i, packNodes)
		vulns, err := getVulnerabilities(query, docChannel)
		if err != nil {
			return nil, err
		}
		i = lastIndex
		totalDepVul = append(totalDepVul, vulns...)
	}

	doc, err := generateDocument(topLevel.Package.Purl, topLevel.Package.Digest, totalDepVul)
	if err != nil {
		return nil, err
	}
	if doc != nil {
		docChannel <- doc
	}
	return totalDepVul, nil
}

func getQuery(lastIndex int, packNodes []assembler.PackageNode) (osv_query.BatchedQuery, int) {
	var query osv_query.BatchedQuery
	var stoppedIndex int
	j := 1
	// limit of 1000 per batch query
	for i := lastIndex; i < len(packNodes); i++ {
		purlQuery := osv_query.MakePURLRequest(packNodes[i].Purl)
		purlQuery.Package.PURL = packNodes[i].Purl
		purlQuery.Package.Digest = packNodes[i].Digest
		query.Queries = append(query.Queries, purlQuery)
		j++
		if j == 1000 {
			stoppedIndex = i
			return query, stoppedIndex
		}
	}
	stoppedIndex = len(packNodes)
	return query, stoppedIndex
}

func getVulnerabilities(query osv_query.BatchedQuery, docChannel chan<- *processor.Document) ([]osv_scanner.Entry, error) {

	resp, err := osv_query.MakeRequest(query)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %v", err)
	}
	totalDepVul := []osv_scanner.Entry{}
	for i, query := range query.Queries {
		response := resp.Results[i]
		totalDepVul = append(totalDepVul, response.Vulns...)
		doc, err := generateDocument(query.Package.PURL, query.Package.Digest, response.Vulns)
		if err != nil {
			return nil, err
		}
		docChannel <- doc
	}
	return totalDepVul, nil
}

func generateDocument(purl string, digest []string, vulns []osv_scanner.Entry) (*processor.Document, error) {
	payload, err := json.Marshal(createAttestation(purl, digest, vulns))
	if err != nil {
		return nil, err
	}
	doc := &processor.Document{
		Blob:   payload,
		Type:   processor.DocumentITE6Vul,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: INVOC_URI,
			Source:    INVOC_URI,
		},
	}
	return doc, nil
}

func createAttestation(packageURL string, digests []string, vulns []osv_scanner.Entry) *attestation_vuln.VulnerabilityStatement {
	currentTime := time.Now()
	var subjects []intoto.Subject

	attestation := &attestation_vuln.VulnerabilityStatement{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: attestation_vuln.PredicateVuln,
		},
		Predicate: attestation_vuln.VulnerabilityPredicate{
			Invocation: attestation_vuln.Invocation{
				Uri:        INVOC_URI,
				ProducerID: PRODUCER_ID,
			},
			Scanner: attestation_vuln.Scanner{
				Uri:     URI,
				Version: VERSION,
			},
			Metadata: attestation_vuln.Metadata{
				ScannedOn: &currentTime,
			},
		},
	}

	for _, digest := range digests {
		digestSplit := strings.Split(digest, ":")
		subjects = append(subjects, intoto.Subject{
			Name: packageURL,
			Digest: slsa.DigestSet{
				digestSplit[0]: digestSplit[1],
			},
		})
	}
	if len(digests) == 0 {
		subjects = append(subjects, intoto.Subject{
			Name: packageURL,
		})
	}

	attestation.StatementHeader.Subject = subjects

	for _, vuln := range vulns {
		attestation.Predicate.Scanner.Result = append(attestation.Predicate.Scanner.Result, attestation_vuln.Result{
			VulnerabilityId: vuln.ID,
		})
	}
	return attestation
}
