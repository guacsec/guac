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

package oci

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/pkg/errors"
)

func Test_ociCollector_RetrieveArtifacts(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		ociValues []string
		poll      bool
		interval  time.Duration
	}

	tests := []struct {
		name       string
		fields     fields
		wantErr    bool
		errMessage error
		want       []*processor.Document
	}{{
		name: "multi-platform sbom",
		fields: fields{
			ociValues: []string{
				"ghcr.io/guacsec/go-multi-test:7ddfb3e035b42cd70649cc33393fe32c",
			},
			poll:     false,
			interval: 0,
		},
		want: []*processor.Document{
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIGoSPDXMulti1),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/go-multi-test:sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10.sbom",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIGoSPDXMulti2),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/go-multi-test:sha256-1bc7e53e25de5c00ecaeca1473ab56bfaf4e39cea747edcf7db467389a287931.sbom",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIGoSPDXMulti3),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/go-multi-test:sha256-534035553d1270a98dab3512fde0987e7709ec6b878c8fd60fdaf0d8e1611979.sbom",
				},
			},
		},
		wantErr: false,
	}, {
		name: "get attestation and sbom",
		fields: fields{
			ociValues: []string{
				"ghcr.io/guacsec/guac-test-image:e26f2e514682726fa808a849c863e5feca71e0c3",
			},
			poll:     false,
			interval: 0,
		},
		want: []*processor.Document{
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIDsseAttExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.att",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCISPDXExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.sbom",
				},
			},
		},
		wantErr: false,
	}, {
		name: "get OCI referrers",
		fields: fields{
			ociValues: []string{
				// used from here: https://github.com/sigstore/cosign/pull/2684
				"ghcr.io/jdolitsky/cosign-pr-demo@sha256:97d731da806109c4f61ac32e8830e13952ca2c65bc7fbfe32babd7d267e633bf",
			},
			poll:     false,
			interval: 0,
		},
		want: []*processor.Document{
			{
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCICosignPRSPDX),
				SourceInformation: processor.SourceInformation{
					Collector: OCICollector,
					Source:    "ghcr.io/jdolitsky/cosign-pr-demo@sha256:e952330096c5349c253bb11c09a25c546ca35d4b2a1bfaac805fee90cbe8fde1",
				},
			},
			{
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCICosignPRSig),
				SourceInformation: processor.SourceInformation{
					Collector: OCICollector,
					Source:    "ghcr.io/jdolitsky/cosign-pr-demo@sha256:478cf2f3284811b500cc3aee71b7d8c3a744917e863a78922674211c75b1e36c",
				},
			},
		}}, {
		name: "tag not specified not polling",
		fields: fields{
			ociValues: []string{
				"ghcr.io/guacsec/guac-test-image",
			},
			poll:     false,
			interval: 0,
		},
		want: []*processor.Document{
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIDsseAttExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.att",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCISPDXExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.sbom",
				},
			},
		},
		wantErr: false,
	}, {
		name: "tag empty string",
		fields: fields{
			ociValues: []string{
				"ghcr.io/guacsec/guac-test-image:",
			},
			poll:     false,
			interval: 0,
		},
		errMessage: errors.New("image tag not specified to fetch"),
		wantErr:    true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewOCICollector(ctx, toDataSource(tt.fields.ociValues), tt.fields.poll, tt.fields.interval)

			var cancel context.CancelFunc
			if tt.fields.poll {
				ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
			}

			if err := collector.RegisterDocumentCollector(g, OCICollector); err != nil &&
				!errors.Is(err, collector.ErrCollectorOverwrite) {
				t.Fatalf("could not register collector: %v", err)
			}

			var collectedDocs []*processor.Document
			em := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}
			eh := func(err error) bool {
				if err != nil {
					if !tt.wantErr {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
					} else if !strings.Contains(err.Error(), tt.errMessage.Error()) {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.errMessage)
					}
				}
				return true
			}

			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collector error handler error: %v", err)
			}

			for i := range tt.want {
				collectedDoc := findDocumentBySource(collectedDocs, tt.want[i].SourceInformation.Source)
				if collectedDoc == nil {
					t.Errorf("g.RetrieveArtifacts() = %v, want %v", nil, tt.want[i])
				}
				result := dochelper.DocTreeEqual(dochelper.DocNode(collectedDoc), dochelper.DocNode(tt.want[i]))
				if !result {
					t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
				}
			}

			if len(collectedDocs) != len(tt.want) {
				t.Fatalf("g.RetrieveArtifacts() = %v, want %v", len(collectedDocs), len(tt.want))
			}

			if g.Type() != OCICollector {
				t.Errorf("g.Type() = %s, want %s", g.Type(), OCICollector)
			}

		})
	}
}

// findDocumentBySource returns the document with the given source
func findDocumentBySource(docs []*processor.Document, source string) *processor.Document {
	for _, d := range docs {
		if d.SourceInformation.Source == source {
			return d
		}
	}
	return nil
}

func toDataSource(ociValues []string) datasource.CollectSource {
	values := []datasource.Source{}
	for _, v := range ociValues {
		values = append(values, datasource.Source{Value: v})
	}

	ds, err := inmemsource.NewInmemDataSources(&datasource.DataSources{
		OciDataSources: values,
	})
	if err != nil {
		panic(err)
	}
	return ds
}
