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
	"github.com/guacsec/guac/pkg/certifier"
	"golang.org/x/time/rate"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/clients" // Import the clients package for rate limiter
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/misc/coordinates"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	PRODUCER_ID string = "guacsec/guac"
	CDCollector string = "clearlydefined"
)

var ErrOSVComponentTypeMismatch error = errors.New("rootComponent type is not []*root_package.PackageNode")

type cdCertifier struct {
	cdHTTPClient *http.Client
}

// NewClearlyDefinedCertifier initializes the cdCertifier
func NewClearlyDefinedCertifier() certifier.Certifier {
	limiter := rate.NewLimiter(rate.Every(time.Minute), 2000)
	client := NewClearlyDefinedHTTPClient(limiter)
	return &cdCertifier{
		cdHTTPClient: client,
	}
}

func NewClearlyDefinedHTTPClient(limiter *rate.Limiter) *http.Client {
	transport := clients.NewRateLimitedTransport(http.DefaultTransport, limiter)
	return &http.Client{Transport: transport}
}

// GetPkgDefinition uses the coordinates to query clearly defined for license definition
func GetPkgDefinition(ctx context.Context, client *http.Client, coordinate *coordinates.Coordinate) (*attestation.Definition, error) {
	logger := logging.FromContext(ctx)

	url := fmt.Sprintf("https://api.clearlydefined.io/definitions/%s/%s/%s/%s/%s", coordinate.CoordinateType, coordinate.Provider,
		coordinate.Namespace, coordinate.Name, coordinate.Revision)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new request with error: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response from clearly defined API with error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			logger.Debugf("package license definition not found for: %s/%s/%s/%s/%s", coordinate.CoordinateType, coordinate.Provider,
				coordinate.Namespace, coordinate.Name, coordinate.Revision)
			return nil, nil
		}
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

	if definition.Described.ReleaseDate == "" {
		return nil, nil
	}

	return &definition, nil
}

// GetSrcDefinition uses the source coordinates found from the package definition to query clearly defined for license definition
func GetSrcDefinition(ctx context.Context, client *http.Client, defType, provider, namespace, name, revision string) (*attestation.Definition, error) {
	logger := logging.FromContext(ctx)
	url := fmt.Sprintf("https://api.clearlydefined.io/definitions/%s/%s/%s/%s/%s", defType, provider, namespace, name, revision)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Fatalln(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response from clearly defined API with error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			// log the error when not found but don't return the error to continue the loop
			logger.Debugf("source license definition not found for: %s/%s/%s/%s/%s", defType, provider, namespace, name, revision)
			return nil, nil
		}
		// otherwise return an error
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

	if definition.Described.ReleaseDate == "" {
		return nil, nil
	}

	return &definition, nil
}

// CertifyComponent takes in the root component from the gauc database and does a recursive scan
// to generate clearly defined attestations
func (c *cdCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return ErrOSVComponentTypeMismatch
	}

	packMap := map[string][]*root_package.PackageNode{}
	for _, node := range packageNodes {
		// skip any purls that are generated by GUAC as they will not be found in clearly defined
		if strings.Contains(node.Purl, "pkg:guac") {
			continue
		}
		if _, ok := packMap[node.Purl]; !ok {
			coordinate, err := coordinates.ConvertPurlToCoordinate(node.Purl)
			if err != nil {
				logger.Errorf("failed to parse purl into coordinate with error: %v", err)
				continue
			}
			definition, err := GetPkgDefinition(ctx, c.cdHTTPClient, coordinate)
			if err != nil {
				return fmt.Errorf("failed get package definition from clearly defined with error: %w", err)
			}
			// if definition for the package is not found, continue to the next package
			if definition == nil {
				continue
			}
			if err := generateDocument(node.Purl, definition, docChannel); err != nil {
				return fmt.Errorf("could not generate document from OSV results: %w", err)
			}
			packMap[node.Purl] = append(packMap[node.Purl], node)
			if definition.Described.SourceLocation != nil {
				srcDefinition, err := GetSrcDefinition(ctx, c.cdHTTPClient, definition.Described.SourceLocation.Type, definition.Described.SourceLocation.Provider,
					definition.Described.SourceLocation.Namespace, definition.Described.SourceLocation.Name, definition.Described.SourceLocation.Revision)
				if err != nil {
					return fmt.Errorf("failed get source definition from clearly defined with error: %w", err)
				}

				if srcDefinition == nil {
					continue
				}

				srcInput := helpers.SourceToSourceInput(definition.Described.SourceLocation.Type, definition.Described.SourceLocation.Namespace,
					definition.Described.SourceLocation.Name, &definition.Described.SourceLocation.Revision)

				if err := generateDocument(helpers.SrcClientKey(srcInput).NameId, srcDefinition, docChannel); err != nil {
					return fmt.Errorf("could not generate document from OSV results: %w", err)
				}
			}
		}
	}
	return nil
}

// generateDocument generates the actual clearly defined attestation
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
			Collector:   CDCollector,
			Source:      CDCollector,
			DocumentRef: events.GetDocRef(payload),
		},
	}
	docChannel <- doc
	return nil
}

func CreateAttestation(purl string, definition *attestation.Definition, currentTime time.Time) *attestation.ClearlyDefinedStatement {
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
