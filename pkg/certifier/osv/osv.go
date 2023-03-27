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
	"time"

	osv_scanner "github.com/google/osv-scanner/pkg/osv"
	"github.com/guacsec/guac/pkg/certifier"
	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/handler/processor"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
)

const (
	URI         string = "osv.dev"
	VERSION     string = "0.0.14"
	INVOC_URI   string = "guac"
	PRODUCER_ID string = "guacsec/guac"
)

var ErrOSVComponenetTypeMismatch error = fmt.Errorf("rootComponent type is not []*root_package.PackageNode")

type osvCertifier struct {
	packageNodes []*root_package.PackageNode
}

// NewOSVCertificationParser initializes the OSVCertifier
func NewOSVCertificationParser() certifier.Certifier {
	return &osvCertifier{}
}

// CertifyComponent takes in the root component from the gauc database and does a recursive scan
// to generate vulnerability attestations
func (o *osvCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	if component, ok := rootComponent.([]*root_package.PackageNode); ok {
		o.packageNodes = component
	} else {
		return ErrOSVComponenetTypeMismatch
	}

	err := o.certifyHelper(ctx, docChannel)
	if err != nil {
		return err
	}
	return nil
}

func (o *osvCertifier) certifyHelper(ctx context.Context, docChannel chan<- *processor.Document) error {
	var query osv_scanner.BatchedQuery
	packMap := map[string][]*root_package.PackageNode{}
	for _, node := range o.packageNodes {
		if _, ok := packMap[node.Purl]; !ok {
			purlQuery := osv_scanner.MakePURLRequest(node.Purl)
			query.Queries = append(query.Queries, purlQuery)
		}
		packMap[node.Purl] = append(packMap[node.Purl], node)
	}
	err := getVulnerabilities(query, packMap, docChannel)
	if err != nil {
		return err
	}
	return nil
}

func getVulnerabilities(query osv_scanner.BatchedQuery, packMap map[string][]*root_package.PackageNode, docChannel chan<- *processor.Document) error {
	resp, err := osv_scanner.MakeRequest(query)
	if err != nil {
		return fmt.Errorf("scan failed: %v", err)
	}
	for i, query := range query.Queries {
		response := resp.Results[i]
		purl := query.Package.PURL
		err := generateDocument(packMap[purl], response.Vulns, docChannel)
		if err != nil {
			return err
		}
	}
	return nil
}

func generateDocument(packNodes []*root_package.PackageNode, vulns []osv_scanner.MinimalVulnerability, docChannel chan<- *processor.Document) error {
	for _, node := range packNodes {
		payload, err := json.Marshal(createAttestation(node, vulns))
		if err != nil {
			return err
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
		docChannel <- doc
	}
	return nil
}

func createAttestation(packageNode *root_package.PackageNode, vulns []osv_scanner.MinimalVulnerability) *attestation_vuln.VulnerabilityStatement {
	currentTime := time.Now()

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

	subject := intoto.Subject{Name: packageNode.Purl}

	if packageNode.Algorithm != "" && packageNode.Digest != "" {
		subject.Digest = common.DigestSet{
			packageNode.Algorithm: packageNode.Digest,
		}
	}

	attestation.StatementHeader.Subject = []intoto.Subject{subject}

	for _, vuln := range vulns {
		attestation.Predicate.Scanner.Result = append(attestation.Predicate.Scanner.Result, attestation_vuln.Result{
			VulnerabilityId: vuln.ID,
		})
	}
	return attestation
}
