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
	"errors"
	"fmt"
	"net/http"
	"time"

	osv_scanner "github.com/google/osv-scanner/pkg/osv"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"

	"github.com/guacsec/guac/pkg/certifier"
	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/version"
)

const (
	URI         string = "osv.dev"
	VERSION     string = "0.0.14"
	INVOC_URI   string = "guac"
	PRODUCER_ID string = "guacsec/guac"
)

var ErrOSVComponenetTypeMismatch error = errors.New("rootComponent type is not []*root_package.PackageNode")

type osvCertifier struct {
	osvHTTPClient *http.Client
}

// NewOSVCertificationParser initializes the OSVCertifier
func NewOSVCertificationParser() certifier.Certifier {
	return &osvCertifier{
		osvHTTPClient: &http.Client{
			Transport: version.UATransport,
		},
	}
}

// CertifyComponent takes in the root component from the gauc database and does a recursive scan
// to generate vulnerability attestations
func (o *osvCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return ErrOSVComponenetTypeMismatch
	}

	var query osv_scanner.BatchedQuery
	packMap := map[string][]*root_package.PackageNode{}
	for _, node := range packageNodes {
		if _, ok := packMap[node.Purl]; !ok {
			purlQuery := osv_scanner.MakePURLRequest(node.Purl)
			query.Queries = append(query.Queries, purlQuery)
		}
		packMap[node.Purl] = append(packMap[node.Purl], node)
	}

	resp, err := osv_scanner.MakeRequestWithClient(query, o.osvHTTPClient)
	if err != nil {
		return fmt.Errorf("osv.dev batched request failed: %w", err)
	}
	for i, query := range query.Queries {
		response := resp.Results[i]
		purl := query.Package.PURL
		if err := generateDocument(packMap[purl], response.Vulns, docChannel); err != nil {
			return fmt.Errorf("could not generate document from OSV results: %w", err)
		}
	}
	return nil
}

func generateDocument(packNodes []*root_package.PackageNode, vulns []osv_scanner.MinimalVulnerability, docChannel chan<- *processor.Document) error {
	for _, node := range packNodes {
		payload, err := json.Marshal(createAttestation(node, vulns))
		if err != nil {
			return fmt.Errorf("unable to marshal attestation: %w", err)
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
