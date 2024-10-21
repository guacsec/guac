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

package eol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/clients"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"golang.org/x/time/rate"
)

var (
	eolAPIBase                   = "https://endoflife.date/api"
	ErrEOLComponenetTypeMismatch = errors.New("rootComponent type is not []*root_package.PackageNode")
)

const (
	EOLCollector   = "endoflife.date"
	rateLimit      = 10
	rateLimitBurst = 1
)

type eolCertifier struct {
	client *http.Client
}

// EOLStringOrBool represents a value that can be either a string, boolean, or null
type EOLStringOrBool struct {
	value interface{}
}

// NewStringValue creates a EOLStringOrBool from a string
func NewStringValue(s string) EOLStringOrBool {
	return EOLStringOrBool{value: s}
}

// NewBoolValue creates a EOLStringOrBool from a bool
func NewBoolValue(b bool) EOLStringOrBool {
	return EOLStringOrBool{value: b}
}

// UnmarshalJSON implements json.Unmarshaler
func (f *EOLStringOrBool) UnmarshalJSON(data []byte) error {
	// Try string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		f.value = s
		return nil
	}

	// Try boolean
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		f.value = b
		return nil
	}

	// Try null
	var n interface{}
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	// If it's null, leave value as nil
	f.value = n
	return nil
}

// IsString returns true if the value is a string
func (f *EOLStringOrBool) IsString() bool {
	_, ok := f.value.(string)
	return ok
}

// IsBool returns true if the value is a boolean
func (f *EOLStringOrBool) IsBool() bool {
	_, ok := f.value.(bool)
	return ok
}

// String returns the string value or empty string if not a string
func (f *EOLStringOrBool) String() string {
	s, ok := f.value.(string)
	if !ok {
		return ""
	}
	return s
}

// Bool returns a boolean value:
// - If value is bool: returns that value
// - If value is string: tries to parse as date and compares with current time
// - Otherwise: returns false
func (f *EOLStringOrBool) Bool() bool {
	// First try as boolean
	if b, ok := f.value.(bool); ok {
		return b
	}

	// Then try as string
	if s, ok := f.value.(string); ok {
		// If string is empty or "false", return false
		if s == "" || strings.EqualFold(s, "false") {
			return false
		}

		// If string is "true", return true
		if strings.EqualFold(s, "true") {
			return true
		}

		// Try to parse as date
		if t, err := time.Parse("2006-01-02", s); err == nil {
			// Compare with current time to determine if EOL
			return time.Now().After(t)
		}
	}

	return false
}

// ToBool converts the value to a boolean based on type:
// - bool: returns the value
// - string: returns true if non-empty
// - nil: returns false
func (f *EOLStringOrBool) ToBool() bool {
	switch v := f.value.(type) {
	case bool:
		return v
	case string:
		return v != "" && v != "false"
	default:
		return false
	}
}

// CycleData represents the endoflife.date API data type for a cycle
type CycleData struct {
	Cycle        string          `json:"cycle"`
	ReleaseDate  string          `json:"releaseDate"`
	EOL          EOLStringOrBool `json:"eol"` // Can be string or boolean
	Latest       string          `json:"latest"`
	Link         *string         `json:"link"`         // Can be null
	LTS          EOLStringOrBool `json:"lts"`          // Can be string or boolean
	Support      EOLStringOrBool `json:"support"`      // Can be string or boolean
	Discontinued EOLStringOrBool `json:"discontinued"` // Can be string or boolean
}

// EOLData is a list of CycleData, the response from the endoflife.date API
type EOLData = []CycleData

func NewEOLCertifier() certifier.Certifier {
	limiter := rate.NewLimiter(rate.Every(time.Second/time.Duration(rateLimit)), rateLimitBurst)
	client := &http.Client{
		Transport: clients.NewRateLimitedTransport(http.DefaultTransport, limiter),
	}
	return &eolCertifier{client: client}
}

func (e *eolCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return ErrEOLComponenetTypeMismatch
	}

	var purls []string
	for _, node := range packageNodes {
		purls = append(purls, node.Purl)
	}

	if _, err := EvaluateEOLResponse(ctx, e.client, purls, docChannel); err != nil {
		return fmt.Errorf("could not generate document from EOL results: %w", err)
	}
	return nil
}

func EvaluateEOLResponse(ctx context.Context, client *http.Client, purls []string, docChannel chan<- *processor.Document) ([]*processor.Document, error) {
	packMap := map[string]bool{}
	var generatedEOLDocs []*processor.Document

	products, err := fetchAllProducts(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch all products: %w", err)
	}

	for _, purl := range purls {
		if strings.Contains(purl, "pkg:guac") {
			continue
		}
		if _, ok := packMap[purl]; ok {
			continue
		}

		product, found := findMatchingProduct(purl, products)
		if !found {
			continue
		}

		eolData, err := fetchProductEOL(ctx, client, product)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch EOL data for %s: %w", product, err)
		}

		cycle, version := extractCycleAndVersion(purl)
		var relevantCycle *CycleData
		for i := range eolData {
			if eolData[i].Cycle == cycle {
				relevantCycle = &eolData[i]
				break
			}
		}

		if relevantCycle == nil && len(eolData) > 0 {
			// If no matching cycle is found, use the latest (first in the list)
			relevantCycle = &eolData[0]
		}

		if relevantCycle != nil {
			currentTime := time.Now()

			// Get EOL status and date
			isEOL := relevantCycle.EOL.Bool()
			eolDateStr := relevantCycle.EOL.String()

			statement := &attestation.EOLStatement{
				Statement: attestationv1.Statement{
					Type:          attestationv1.StatementTypeUri,
					PredicateType: attestation.PredicateEOL,
					Subject:       []*attestationv1.ResourceDescriptor{{Uri: purl}},
				},
				Predicate: attestation.EOLPredicate{
					Product:     product,
					Cycle:       relevantCycle.Cycle,
					Version:     version,
					IsEOL:       isEOL,
					EOLDate:     eolDateStr,
					LTS:         relevantCycle.LTS.Bool(),
					Latest:      relevantCycle.Latest,
					ReleaseDate: relevantCycle.ReleaseDate,
					Metadata: attestation.EOLMetadata{
						ScannedOn: &currentTime,
					},
				},
			}

			payload, err := json.Marshal(statement)
			if err != nil {
				return nil, fmt.Errorf("unable to marshal attestation: %w", err)
			}

			doc := &processor.Document{
				Blob:   payload,
				Type:   processor.DocumentITE6EOL,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector:   EOLCollector,
					Source:      EOLCollector,
					DocumentRef: events.GetDocRef(payload),
				},
			}

			if docChannel != nil {
				docChannel <- doc
			}
			generatedEOLDocs = append(generatedEOLDocs, doc)
		}

		packMap[purl] = true
	}

	return generatedEOLDocs, nil
}

func fetchAllProducts(ctx context.Context, client *http.Client) ([]string, error) {
	resp, err := client.Get(fmt.Sprintf("%s/all.json", eolAPIBase))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var products []string
	if err := json.NewDecoder(resp.Body).Decode(&products); err != nil {
		return nil, err
	}

	return products, nil
}

func fetchProductEOL(ctx context.Context, client *http.Client, product string) (EOLData, error) {
	resp, err := client.Get(fmt.Sprintf("%s/%s.json", eolAPIBase, product))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EOL data for %s: %w", product, err)
	}
	defer resp.Body.Close()

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 status code (%d) for product %s", resp.StatusCode, product)
	}

	var rawData []map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&rawData); err != nil {
		return nil, fmt.Errorf("failed to decode EOL data for %s: %w", product, err)
	}

	eolData := make(EOLData, len(rawData))
	for i, item := range rawData {
		var cycle CycleData

		// Decode the simple string fields directly
		if v, ok := item["cycle"]; ok {
			if err := json.Unmarshal(v, &cycle.Cycle); err != nil {
				return nil, fmt.Errorf("failed to decode cycle for %s: %w", product, err)
			}
		}
		if v, ok := item["releaseDate"]; ok {
			if err := json.Unmarshal(v, &cycle.ReleaseDate); err != nil {
				return nil, fmt.Errorf("failed to decode releaseDate for %s: %w", product, err)
			}
		}
		if v, ok := item["latest"]; ok {
			if err := json.Unmarshal(v, &cycle.Latest); err != nil {
				return nil, fmt.Errorf("failed to decode latest for %s: %w", product, err)
			}
		}

		// Handle the flexible type fields
		if v, ok := item["eol"]; ok {
			var eol EOLStringOrBool
			if err := json.Unmarshal(v, &eol); err != nil {
				return nil, fmt.Errorf("failed to decode eol for %s: %w", product, err)
			}
			cycle.EOL = eol
		}
		if v, ok := item["lts"]; ok {
			var lts EOLStringOrBool
			if err := json.Unmarshal(v, &lts); err != nil {
				return nil, fmt.Errorf("failed to decode lts for %s: %w", product, err)
			}
			cycle.LTS = lts
		}
		if v, ok := item["support"]; ok {
			var support EOLStringOrBool
			if err := json.Unmarshal(v, &support); err != nil {
				return nil, fmt.Errorf("failed to decode support for %s: %w", product, err)
			}
			cycle.Support = support
		}
		if v, ok := item["discontinued"]; ok {
			var discontinued EOLStringOrBool
			if err := json.Unmarshal(v, &discontinued); err != nil {
				return nil, fmt.Errorf("failed to decode discontinued for %s: %w", product, err)
			}
			cycle.Discontinued = discontinued
		}

		// Optional link field
		if v, ok := item["link"]; ok {
			var link string
			if err := json.Unmarshal(v, &link); err != nil {
				return nil, fmt.Errorf("failed to decode link for %s: %w", product, err)
			}
			cycle.Link = &link
		}

		eolData[i] = cycle
	}

	return eolData, nil
}

func findMatchingProduct(purl string, products []string) (string, bool) {
	parts := strings.Split(purl, "/")
	if len(parts) < 2 {
		return "", false
	}

	packageName := strings.Split(parts[1], "@")[0]
	packageName = strings.ToLower(packageName)

	for _, product := range products {
		if strings.Contains(packageName, product) || strings.Contains(product, packageName) {
			return product, true
		}
	}

	return "", false
}

func extractCycleAndVersion(purl string) (string, string) {
	parts := strings.Split(purl, "@")
	if len(parts) < 2 {
		return "", ""
	}

	version := parts[1]
	versionParts := strings.Split(version, ".")

	if len(versionParts) > 0 {
		return versionParts[0], version
	}

	return "", version
}
