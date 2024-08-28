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
	osv_scanner "github.com/google/osv-scanner/pkg/osv"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func TestClearlyDefined(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	tests := []struct {
		name          string
		rootComponent interface{}
		want          []*processor.Document
		wantErr       bool
		errMessage    error
	}{{
		name: "query and generate attestation from clearly defined",
		//
		rootComponent: []*root_package.PackageNode{&testdata.Text4ShellPackage, &testdata.Log4JPackage, &testdata.RootPackage},
		want: []*processor.Document{
			{
				Blob:   []byte(testdata.ITE6CDCommonText),
				Type:   processor.DocumentITE6ClearlyDefined,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: CDCollector,
					Source:    CDCollector,
				},
			},
			{
				Blob:   []byte(testdata.ITE6CDSourceCommonText),
				Type:   processor.DocumentITE6ClearlyDefined,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: CDCollector,
					Source:    CDCollector,
				},
			},
			{
				Blob:   []byte(testdata.ITE6CDLog4j),
				Type:   processor.DocumentITE6ClearlyDefined,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: CDCollector,
					Source:    CDCollector,
				},
			},
			{
				Blob:   []byte(testdata.ITE6CDSourceLog4j),
				Type:   processor.DocumentITE6ClearlyDefined,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: CDCollector,
					Source:    CDCollector,
				},
			},
		},
		wantErr: false,
	}, {
		name:          "unknown purl",
		rootComponent: []*root_package.PackageNode{{Purl: "pkg:maven/commons/commons12text@1.9"}},
		wantErr:       false,
	}, {
		name:          "bad type",
		rootComponent: map[string]string{},
		wantErr:       true,
		errMessage:    ErrOSVComponentTypeMismatch,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClearlyDefinedCertifier()
			collectedDocs := []*processor.Document{}
			docChan := make(chan *processor.Document, 1)
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- c.CertifyComponent(ctx, tt.rootComponent, docChan)
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

func TestCDCertifierRateLimiter(t *testing.T) {
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

	cert := NewClearlyDefinedCertifier()

	// Make requests to the mock server
	start := time.Now()
	for i := 0; i < rateLimit+1; i++ {
		req, err := http.NewRequestWithContext(ctx, "POST", server.URL, nil)
		assert.NoError(t, err)

		resp, err := cert.(*cdCertifier).cdHTTPClient.Do(req)
		assert.NoError(t, err)
		resp.Body.Close()
	}
	duration := time.Since(start)

	// Check if the processing time is close to or slightly over 1 minute
	assert.True(t, duration >= 59*time.Second && duration <= 65*time.Second,
		"Expected duration to be close to 60 seconds, got %v", duration)

	// Check if the log contains any rate limiting messages
	logOutput := logBuffer.String()

	assert.Contains(t, logOutput, "Rate limit exceeded")
}
