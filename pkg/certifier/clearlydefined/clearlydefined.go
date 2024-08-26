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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/clients" // Import the clients package for rate limiter
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/misc/coordinates"
	"github.com/guacsec/guac/pkg/version"

	attestationv1 "github.com/in-toto/attestation/go/v1"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary
var rateLimit = 2000
var rateLimitInterval = time.Minute

const (
	PRODUCER_ID string = "guacsec/guac"
	CDCollector string = "clearlydefined"
)

var ErrComponentTypeMismatch error = errors.New("rootComponent type is not []*root_package.PackageNode")

type cdCertifier struct {
	cdHTTPClient *http.Client
}

// NewClearlyDefinedCertifier initializes the cdCertifier
func NewClearlyDefinedCertifier() certifier.Certifier {
	limiter := rate.NewLimiter(rate.Every(rateLimitInterval), rateLimit)
	client := NewClearlyDefinedHTTPClient(limiter)
	return &cdCertifier{
		cdHTTPClient: client,
	}
}

func NewClearlyDefinedHTTPClient(limiter *rate.Limiter) *http.Client {
	transport := clients.NewRateLimitedTransport(version.UATransport, limiter)
	return &http.Client{Transport: transport}
}

// getDefinitions uses the coordinates to query clearly defined for license definition
func getDefinitions(_ context.Context, client *http.Client, purls []string, coordinates []string) (map[string]*attestation.Definition, error) {

	coordinateToPurl := make(map[string]string)
	for i, purl := range purls {
		coordinateToPurl[coordinates[i]] = purl
	}

	definitionMap := make(map[string]*attestation.Definition)

	// Convert coordinates to JSON
	jsonData, err := json.Marshal(coordinates)
	if err != nil {
		log.Fatalf("Error marshalling coordinates: %v", err)
	}

	// Make the POST request
	resp, err := client.Post("https://api.clearlydefined.io/definitions", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Error making POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// otherwise return an error
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var definitions map[string]*attestation.Definition
	if err := json.Unmarshal(body, &definitions); err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	if len(purls) != len(definitions) {
		return nil, fmt.Errorf("failed to get expected responses back! Purl count: %d, returned definition count %d", len(purls), len(definitions))
	}

	for coordinate, definition := range definitions {
		definitionMap[coordinateToPurl[coordinate]] = definition
	}

	return definitionMap, nil
}

func EvaluateClearlyDefinedDefinition(ctx context.Context, client *http.Client, purls []string) ([]*processor.Document, error) {
	logger := logging.FromContext(ctx)
	var batchCoordinates []string
	var queryPurls []string
	packMap := map[string]bool{}
	var generatedCDDocs []*processor.Document

	for _, purl := range purls {
		// skip any purls that are generated by GUAC as they will not be found in clearly defined
		if strings.Contains(purl, "pkg:guac") {
			continue
		}
		if _, ok := packMap[purl]; !ok {
			coordinate, err := coordinates.ConvertPurlToCoordinate(purl)
			if err != nil {
				logger.Debugf("failed to parse purl into coordinate with error: %v", err)
				continue
			}
			packMap[purl] = true
			queryPurls = append(queryPurls, purl)
			batchCoordinates = append(batchCoordinates, coordinate.ToString())
		}
	}
	if genCDDocs, err := generateDefinitions(ctx, client, batchCoordinates, queryPurls); err != nil {
		return nil, fmt.Errorf("generateDefinitions failed with error: %w", err)
	} else {
		generatedCDDocs = append(generatedCDDocs, genCDDocs...)
	}

	return generatedCDDocs, nil
}

func generateDefinitions(ctx context.Context, client *http.Client, batchCoordinates, queryPurls []string) ([]*processor.Document, error) {
	var generatedCDDocs []*processor.Document
	if len(batchCoordinates) > 0 {
		definitionMap, err := getDefinitions(ctx, client, queryPurls, batchCoordinates)
		if err != nil {
			return nil, fmt.Errorf("failed get package definition from clearly defined with error: %w", err)
		}

		if genCDPkgDocs, err := generateDocument(definitionMap); err != nil {
			return nil, fmt.Errorf("evaluateDefinitionForSource failed with error: %w", err)
		} else {
			generatedCDDocs = append(generatedCDDocs, genCDPkgDocs...)
		}

		if genCDSrcDocs, err := evaluateDefinitionForSource(ctx, client, definitionMap); err != nil {
			return nil, fmt.Errorf("evaluateDefinitionForSource failed with error: %w", err)
		} else {
			generatedCDDocs = append(generatedCDDocs, genCDSrcDocs...)
		}
	}
	return generatedCDDocs, nil
}

// CertifyComponent takes in the root component from the gauc database and does a recursive scan
// to generate clearly defined attestations
func (c *cdCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return ErrComponentTypeMismatch
	}

	var purls []string
	for _, node := range packageNodes {
		purls = append(purls, node.Purl)
	}

	if genCDDocs, err := EvaluateClearlyDefinedDefinition(ctx, c.cdHTTPClient, purls); err != nil {
		return fmt.Errorf("could not generate document from Clearly Defined results: %w", err)
	} else {
		for _, doc := range genCDDocs {
			docChannel <- doc
		}
	}

	return nil
}

func evaluateDefinitionForSource(ctx context.Context, client *http.Client, definitionMap map[string]*attestation.Definition) ([]*processor.Document, error) {
	sourceMap := map[string]bool{}
	var batchCoordinates []string
	var sourceInputs []string
	for _, definition := range definitionMap {
		if definition.Described.SourceLocation != nil {
			srcInput := helpers.SourceToSourceInput(definition.Described.SourceLocation.Type, definition.Described.SourceLocation.Namespace,
				definition.Described.SourceLocation.Name, &definition.Described.SourceLocation.Revision)

			nameID := helpers.SrcClientKey(srcInput).NameId

			if _, ok := sourceMap[nameID]; !ok {
				coordinate := &coordinates.Coordinate{
					CoordinateType: definition.Described.SourceLocation.Type,
					Provider:       definition.Described.SourceLocation.Provider,
					Namespace:      definition.Described.SourceLocation.Namespace,
					Name:           definition.Described.SourceLocation.Name,
					Revision:       definition.Described.SourceLocation.Revision,
				}
				sourceMap[nameID] = true
				sourceInputs = append(sourceInputs, nameID)
				batchCoordinates = append(batchCoordinates, coordinate.ToString())
			}
		}
	}

	if len(batchCoordinates) > 0 {
		definitionMap, err := getDefinitions(ctx, client, sourceInputs, batchCoordinates)
		if err != nil {
			return nil, fmt.Errorf("failed get source definition from clearly defined with error: %w", err)
		}
		return generateDocument(definitionMap)
	}
	return nil, nil
}

// generateDocument generates the actual clearly defined attestation
func generateDocument(definitionMap map[string]*attestation.Definition) ([]*processor.Document, error) {
	var generatedCDDocs []*processor.Document
	for purl, definition := range definitionMap {
		if definition.Described.ReleaseDate == "" {
			continue
		}
		currentTime := time.Now()
		payload, err := json.Marshal(createAttestation(purl, definition, currentTime))
		if err != nil {
			return nil, fmt.Errorf("unable to marshal attestation: %w", err)
		}
		doc := &processor.Document{
			Blob:   payload,
			Type:   processor.DocumentITE6ClearlyDefined,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector:   CDCollector,
				Source:      CDCollector,
				DocumentRef: events.GetDocRef(payload),
			},
		}
		generatedCDDocs = append(generatedCDDocs, doc)
	}
	return generatedCDDocs, nil
}

func createAttestation(purl string, definition *attestation.Definition, currentTime time.Time) *attestation.ClearlyDefinedStatement {
	attestation := &attestation.ClearlyDefinedStatement{
		Statement: attestationv1.Statement{
			Type:          attestationv1.StatementTypeUri,
			PredicateType: attestation.PredicateClearlyDefined,
		},
		Predicate: attestation.ClearlyDefinedPredicate{
			Definition: *definition,
			Metadata: attestation.Metadata{
				ScannedOn: &currentTime,
			},
		},
	}

	subject := &attestationv1.ResourceDescriptor{Uri: purl}
	attestation.Statement.Subject = append(attestation.Statement.Subject, subject)

	return attestation
}
