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
	"bytes"
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	osv_scanner "github.com/google/osv-scanner/pkg/osv"
	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation/vuln"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	attestationv1 "github.com/in-toto/attestation/go/v1"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func TestOSVCertifier_CertifyVulns(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	tests := []struct {
		name          string
		rootComponent interface{}
		want          []*processor.Document
		wantErr       bool
		errMessage    error
	}{{
		name:          "query and generate attestation for OSV",
		rootComponent: []*root_package.PackageNode{&testdata.Text4ShellPackage, &testdata.SecondLevelPackage, &testdata.Log4JPackage, &testdata.RootPackage},
		want: []*processor.Document{
			{
				Blob:   []byte(testdata.Text4ShellVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: INVOC_URI,
					Source:    INVOC_URI,
				},
			},
			{
				Blob:   []byte(testdata.SecondLevelVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: INVOC_URI,
					Source:    INVOC_URI,
				},
			},
			{
				Blob:   []byte(testdata.Log4JVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: INVOC_URI,
					Source:    INVOC_URI,
				},
			},
			{
				Blob:   []byte(testdata.RootVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: INVOC_URI,
					Source:    INVOC_URI,
				},
			},
		},
		wantErr: false,
	}, {
		name:          "bad type",
		rootComponent: map[string]string{},
		wantErr:       true,
		errMessage:    ErrOSVComponenetTypeMismatch,
	}, {
		name:          "ensure intermediate vulnerabilities are reported",
		rootComponent: []*root_package.PackageNode{&testdata.VertxWebCommonPackage, &testdata.VertxAuthCommonPackage, &testdata.VertxBridgeCommonPackage, &testdata.VertxCoreCommonPackage, &testdata.VertxWebPackage},
		want: []*processor.Document{
			{
				Blob:   []byte(testdata.VertxWebCommonAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: INVOC_URI,
					Source:    INVOC_URI,
				},
			},
			{
				Blob:   []byte(testdata.VertxAuthCommonAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: INVOC_URI,
					Source:    INVOC_URI,
				},
			},
			{
				Blob:   []byte(testdata.VertxBridgeCommonAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: INVOC_URI,
					Source:    INVOC_URI,
				},
			},
			{
				Blob:   []byte(testdata.VertxCoreCommonAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: INVOC_URI,
					Source:    INVOC_URI,
				},
			},
			{
				Blob:   []byte(testdata.VertxWebAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: INVOC_URI,
					Source:    INVOC_URI,
				},
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewOSVCertificationParser()
			collectedDocs := []*processor.Document{}
			docChan := make(chan *processor.Document, 1)
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- o.CertifyComponent(ctx, tt.rootComponent, docChan)
			}()
			numCollectors := 1
			certifiersDone := 0
			var err error
			for certifiersDone < numCollectors {
				select {
				case d := <-docChan:
					collectedDocs = append(collectedDocs, d)
				case err = <-errChan:
					if (err != nil) != tt.wantErr {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
					if err != nil {
						if !errors.Is(err, tt.errMessage) {
							t.Errorf("Certify() errored with message = %v, wanted error message %v", err, tt.errMessage)
						}
						return
					}
					certifiersDone += 1

				}
			}
			// Drain anything left in document channel
			for len(docChan) > 0 {
				d := <-docChan
				collectedDocs = append(collectedDocs, d)
			}
			if err == nil {
				sort.Slice(collectedDocs, func(i, j int) bool {
					uriI, errI := dochelper.ExtractURI(collectedDocs[i].Blob)
					uriJ, errJ := dochelper.ExtractURI(collectedDocs[j].Blob)
					if errI != nil || errJ != nil {
						return false
					}
					return uriI < uriJ
				})
				sort.Slice(tt.want, func(i, j int) bool {
					uriI, errI := dochelper.ExtractURI(tt.want[i].Blob)
					uriJ, errJ := dochelper.ExtractURI(tt.want[j].Blob)
					if errI != nil || errJ != nil {
						return false
					}
					return uriI < uriJ
				})
				if len(collectedDocs) != len(tt.want) {
					t.Errorf("collected docs does not match wanted")
				}
				for i := range collectedDocs {
					result, err := dochelper.DocEqualWithTimestamp(collectedDocs[i], tt.want[i])
					if err != nil {
						t.Error(err)
					}
					if !result {
						t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
					}
				}
			}
		})
	}
}

func Test_createAttestation(t *testing.T) {
	currentTime := time.Now()
	type args struct {
		purl  string
		vulns []osv_scanner.MinimalVulnerability
	}
	tests := []struct {
		name string
		args args
		want *attestation_vuln.VulnerabilityStatement
	}{{
		name: "default",
		args: args{
			purl: "",
			vulns: []osv_scanner.MinimalVulnerability{
				{
					ID: "testId",
				},
			},
		},
		want: &attestation_vuln.VulnerabilityStatement{
			Statement: attestationv1.Statement{
				Type:          attestationv1.StatementTypeUri,
				PredicateType: attestation_vuln.PredicateVuln,
				Subject:       []*attestationv1.ResourceDescriptor{{Name: ""}},
			},
			Predicate: attestation_vuln.VulnerabilityPredicate{
				Scanner: attestation_vuln.Scanner{
					Uri:     URI,
					Version: VERSION,
					Result:  []attestation_vuln.Result{{Id: "testId"}},
				},
				Metadata: attestation_vuln.Metadata{
					ScanStartedOn: &currentTime,
					ScanFinishedOn: &currentTime,
				},
			},
		},
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			currentTime := time.Now()
			got := createAttestation(test.args.purl, test.args.vulns, currentTime)
			if !deepEqualIgnoreTimestamp(got, test.want) {
				t.Errorf("createAttestation() = %v, want %v", got, test.want)
			}
		})
	}
}

func deepEqualIgnoreTimestamp(a, b *attestation_vuln.VulnerabilityStatement) bool {
	// create a copy of a and b, and set the ScannedOn field to nil because the timestamps will be different
	aCopy := a
	bCopy := b
	aCopy.Predicate.Metadata.ScanStartedOn = nil
	bCopy.Predicate.Metadata.ScanStartedOn = nil
	aCopy.Predicate.Metadata.ScanFinishedOn = nil
	bCopy.Predicate.Metadata.ScanFinishedOn = nil

	// use DeepEqual to compare the copies
	return reflect.DeepEqual(aCopy, bCopy)
}

func TestOSVCertifierRateLimiter(t *testing.T) {
	// Set up the logger
	var logBuffer bytes.Buffer
	encoderConfig := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(&logBuffer),
		zap.DebugLevel,
	)
	logger := zap.New(core).Sugar()

	ctx := context.Background()
	ctx = context.WithValue(ctx, logging.ChildLoggerKey, logger)

	// Set up a mock OSV server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := osv_scanner.BatchedResponse{
			Results: []osv_scanner.MinimalResponse{
				{
					Vulns: []osv_scanner.MinimalVulnerability{
						{
							ID: "TestID",
						},
					},
				},
			},
		}
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	oldRateLimit := rateLimit
	rateLimit = 5
	oldRateLimitInterval := rateLimitInterval
	rateLimitInterval = time.Second
	defer func() {
		rateLimit = oldRateLimit
		rateLimitInterval = oldRateLimitInterval
	}()

	cert := NewOSVCertificationParser()

	// Make requests to the mock server
	for i := 0; i < rateLimit+1; i++ {
		req, err := http.NewRequestWithContext(ctx, "POST", server.URL, nil)
		assert.NoError(t, err)

		resp, err := cert.(*osvCertifier).osvHTTPClient.Do(req)
		assert.NoError(t, err)
		resp.Body.Close()
	}

	// Check if the log contains any rate limiting messages
	logOutput := logBuffer.String()

	assert.Contains(t, logOutput, "Rate limit exceeded")
}
