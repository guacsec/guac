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
	PRODUCER_ID string = "guecsec/guac"
)

type osvCertifier struct {
	rootComponents *certifier.Component
}

// NewOSVCertificationParser initializes the OSVCertifier
func NewOSVCertificationParser() certifier.Certifier {
	return &osvCertifier{}
}

// CertifyVulns takes in the root component from the gauc database and does a recursive scan
// to generate vulnerability attestations
func (o *osvCertifier) CertifyVulns(ctx context.Context, rootComponent *certifier.Component, docChannel chan<- *processor.Document) error {
	o.rootComponents = rootComponent
	_, err := o.certifyHelper(ctx, rootComponent, rootComponent.DepPackages, docChannel)
	if err != nil {
		return err
	}
	return nil
}

func (o *osvCertifier) certifyHelper(ctx context.Context, topLevel *certifier.Component, depPackages []*certifier.Component, docChannel chan<- *processor.Document) ([]osv_scanner.Entry, error) {
	packNodes := []assembler.PackageNode{}
	totalDepVul := []osv_scanner.Entry{}
	for _, depPack := range depPackages {
		if len(depPack.DepPackages) > 0 {
			depVulns, err := o.certifyHelper(ctx, depPack, depPack.DepPackages, docChannel)
			if err != nil {
				return nil, nil
			}
			totalDepVul = append(totalDepVul, depVulns...)
		} else {
			packNodes = append(packNodes, depPack.CurPackage)
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

	doc, err := generateDocument(topLevel.CurPackage.Purl, topLevel.CurPackage.Digest, totalDepVul)
	if err != nil {
		return nil, err
	}
	docChannel <- doc
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
	payload, err := generateOSVCertifyPredicateBlob(createAttestation(purl, digest, vulns))
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

func createAttestation(purl string, digest []string, vulns []osv_scanner.Entry) *attestation_vuln.VulnerabilityStatement {
	currentTime := time.Now()
	var subjects []intoto.Subject

	attestation := &attestation_vuln.VulnerabilityStatement{}
	attestation.StatementHeader.Type = intoto.StatementInTotoV01
	attestation.StatementHeader.PredicateType = attestation_vuln.PredicateVuln
	if len(digest) > 0 {
		for _, digest := range digest {
			digestSplit := strings.Split(digest, ":")
			subjects = append(subjects, intoto.Subject{
				Name: purl,
				Digest: slsa.DigestSet{
					digestSplit[0]: digestSplit[1],
				},
			})
		}
	} else {
		subjects = append(subjects, intoto.Subject{
			Name: purl,
		})
	}

	attestation.StatementHeader.Subject = subjects
	attestation.Predicate.Invocation.Uri = INVOC_URI
	attestation.Predicate.Invocation.ProducerID = PRODUCER_ID
	attestation.Predicate.Scanner.Uri = URI
	attestation.Predicate.Scanner.Version = VERSION
	attestation.Predicate.Metadata.ScannedOn = &currentTime

	for _, vuln := range vulns {
		attestation.Predicate.Scanner.Result = append(attestation.Predicate.Scanner.Result, attestation_vuln.Result{
			VulnerabilityId: vuln.ID,
		})
	}
	return attestation
}

func generateOSVCertifyPredicateBlob(p *attestation_vuln.VulnerabilityStatement) ([]byte, error) {
	blob, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return blob, nil
}
