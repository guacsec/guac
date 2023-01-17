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
	"reflect"
	"testing"
	"time"

	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	osv_scanner "golang.org/x/vuln/osv"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func TestOSVCertifier_CertifyVulns(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	tests := []struct {
		name          string
		rootComponent *certifier.Component
		want          []*processor.Document
		wantErr       bool
	}{{
		name:          "query and generate attestation for OSV",
		rootComponent: testdata.RootComponent,
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
			for certifiersDone < numCollectors {
				select {
				case d := <-docChan:
					collectedDocs = append(collectedDocs, d)
				case err := <-errChan:
					if (err != nil) != tt.wantErr {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
					if err != nil {
						t.Errorf("collector ended with error: %v", err)
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
			for i := range collectedDocs {
				result, err := dochelper.DocEqualWithTimestamp(collectedDocs[i], tt.want[i])
				if err != nil {
					t.Error(err)
				}
				if !result {
					t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
				}
			}
		})
	}
}

func Test_createAttestation(t *testing.T) {
	currentTime := time.Now()
	type args struct {
		projectURL string
		digests    []string
		vulns      []osv_scanner.Entry
	}
	tests := []struct {
		name string
		args args
		want *attestation_vuln.VulnerabilityStatement
	}{
		{
			name: "default",
			args: args{
				vulns: []osv_scanner.Entry{
					{
						ID: "testId",
					},
				},
			},
			want: &attestation_vuln.VulnerabilityStatement{
				StatementHeader: intoto.StatementHeader{
					Type:          intoto.StatementInTotoV01,
					PredicateType: attestation_vuln.PredicateVuln,
					Subject:       []intoto.Subject{{Name: ""}},
				},
				Predicate: attestation_vuln.VulnerabilityPredicate{
					Invocation: attestation_vuln.Invocation{
						Uri:        INVOC_URI,
						ProducerID: PRODUCER_ID,
					},
					Scanner: attestation_vuln.Scanner{
						Uri:     URI,
						Version: VERSION,
						Result:  []attestation_vuln.Result{{VulnerabilityId: "testId"}},
					},
					Metadata: attestation_vuln.Metadata{
						ScannedOn: &currentTime,
					},
				},
			},
		},
		{
			name: "has digests",
			args: args{
				digests: []string{"test:Digest"},
			},
			want: &attestation_vuln.VulnerabilityStatement{
				StatementHeader: intoto.StatementHeader{
					Type:          intoto.StatementInTotoV01,
					PredicateType: attestation_vuln.PredicateVuln,
					Subject: []intoto.Subject{
						{
							Name: "",
							Digest: slsa.DigestSet{
								"test": "Digest",
							},
						},
					},
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
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := createAttestation(test.args.projectURL, test.args.digests, test.args.vulns)
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
	aCopy.Predicate.Metadata.ScannedOn = nil
	bCopy.Predicate.Metadata.ScannedOn = nil

	// use DeepEqual to compare the copies
	return reflect.DeepEqual(aCopy, bCopy)
}
