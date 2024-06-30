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
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	jsoniter "github.com/json-iterator/go"

	intoto "github.com/in-toto/in-toto-golang/in_toto"

	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/version"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	PRODUCER_ID string = "guacsec/guac"
	cdCollector string = "clearlydefined"
)

var ErrOSVComponenetTypeMismatch error = errors.New("rootComponent type is not []*root_package.PackageNode")

type cdCertifier struct {
}

// NewClearlyDefinedCertifier initializes the the cdCertifier
func NewClearlyDefinedCertifier() certifier.Certifier {
	return &cdCertifier{}
}

func getDefinition(defType, namespace, name, revision string) (*attestation.Definition, error) {
	provider := map[string]string{"maven": "mavencentral"}
	url := fmt.Sprintf("https://api.clearlydefined.io/definitions/%s/%s/%s/%s/%s", defType, provider[defType], namespace, name, revision)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(err)
	}
	resp, err := version.UATransport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response from clearly defined API with error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var definition attestation.Definition
	if err := json.Unmarshal(body, &definition); err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	return &definition, nil
}

// CertifyComponent takes in the root component from the gauc database and does a recursive scan
// to generate vulnerability attestations
func (c *cdCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return ErrOSVComponenetTypeMismatch
	}

	packMap := map[string][]*root_package.PackageNode{}
	for _, node := range packageNodes {
		if _, ok := packMap[node.Purl]; !ok {
			pkg, err := helpers.PurlToPkg(node.Purl)
			if err != nil {
				return fmt.Errorf("failed to parse purl with error: %w", err)
			}
			definition, err := getDefinition(pkg.Type, *pkg.Namespace, pkg.Name, *pkg.Version)
			if err != nil {
				return fmt.Errorf("failed get definition from clearly defined with error: %w", err)
			}
			if err := generateDocument(node.Purl, definition, docChannel); err != nil {
				return fmt.Errorf("could not generate document from OSV results: %w", err)
			}

		}
		packMap[node.Purl] = append(packMap[node.Purl], node)
	}

	return nil
}

func generateDocument(purl string, definition *attestation.Definition, docChannel chan<- *processor.Document) error {
	currentTime := time.Now()
	payload, err := json.Marshal(CreateAttestation(purl, definition, currentTime))
	if err != nil {
		return fmt.Errorf("unable to marshal attestation: %w", err)
	}
	doc := &processor.Document{
		Blob:   payload,
		Type:   processor.DocumentITE6ClearlyDefined,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector:   cdCollector,
			Source:      cdCollector,
			DocumentRef: events.GetDocRef(payload),
		},
	}
	docChannel <- doc
	return nil
}

func CreateAttestation(purl string, definition *attestation.Definition, currentTime time.Time) *attestation.ClearlyDefinedStatement {
	attestation := &attestation.ClearlyDefinedStatement{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: attestation.PredicateClearlyDefined,
		},
		Predicate: attestation.ClearlyDefinedPredicate{
			Definition: *definition,
		},
	}

	subject := intoto.Subject{Name: purl}

	attestation.StatementHeader.Subject = []intoto.Subject{subject}

	return attestation
}
