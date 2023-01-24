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

package certify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	nats_test "github.com/guacsec/guac/internal/testing/nats"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	uuid "github.com/satori/go.uuid"
)

type mockQuery struct {
}

// NewMockQuery initializes the mockQuery to query for tests
func newMockQuery() certifier.QueryComponents {
	return &mockQuery{}
}

// GetComponents returns components for test
func (q *mockQuery) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	compChan <- testdata.RootComponent
	return nil
}

type mockUnknownQuery struct {
}

// NewMockQuery initializes the mockQuery to query for tests
func newMockUnknownQuery() certifier.QueryComponents {
	return &mockUnknownQuery{}
}

// GetComponents returns components for test
func (q *mockUnknownQuery) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	compChan <- assembler.AttestationNode{}
	return nil
}

func TestCertify(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	err := RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV)
	if err != nil && !errors.Is(err, errCertifierOverwrite) {
		t.Errorf("unexpected error: %v", err)
	}

	errHandler := func(err error) bool {
		return err == nil
	}

	tests := []struct {
		name       string
		query      certifier.QueryComponents
		want       []*processor.Document
		wantErr    bool
		errMessage error
	}{{
		name:  "query and generate attestation",
		query: newMockQuery(),
		want: []*processor.Document{
			{
				Blob:   []byte(testdata.Text4ShellVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
			{
				Blob:   []byte(testdata.SecondLevelVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
			{
				Blob:   []byte(testdata.Log4JVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
			{
				Blob:   []byte(testdata.RootVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
		},
		wantErr: false,
	}, {
		name:       "unknown type for collected component",
		query:      newMockUnknownQuery(),
		wantErr:    true,
		errMessage: osv.ErrOSVComponenetTypeMismatch,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var collectedDocs []*processor.Document

			emit := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}

			err := Certify(ctx, tt.query, emit, errHandler)
			if (err != nil) != tt.wantErr {
				t.Errorf("Certify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				for i := range collectedDocs {
					result, err := dochelper.DocEqualWithTimestamp(collectedDocs[i], tt.want[i])
					if err != nil {
						t.Error(err)
					}
					if !result {
						t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
					}
				}
			} else {
				if !errors.Is(err, tt.errMessage) {
					t.Errorf("Certify() errored with message = %v, wanted error message %v", err, tt.errMessage)
				}
			}
		})
	}
}

func Test_Publish(t *testing.T) {
	err := RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV)
	if err != nil && !errors.Is(err, errCertifierOverwrite) {
		t.Errorf("unexpected error: %v", err)
	}
	expectedDocTree := dochelper.DocNode(&testdata.Ite6SLSADoc)

	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	ctx := context.Background()
	jetStream := emitter.NewJetStream(url, "", "")
	ctx, err = jetStream.JetStreamInit(ctx)
	if err != nil {
		t.Fatalf("unexpected error initializing jetstream: %v", err)
	}
	err = jetStream.RecreateStream(ctx)
	if err != nil {
		t.Fatalf("unexpected error recreating jetstream: %v", err)
	}
	defer jetStream.Close()
	err = Publish(ctx, &testdata.Ite6SLSADoc)
	if err != nil {
		t.Fatalf("unexpected error on emit: %v", err)
	}

	var cancel context.CancelFunc

	ctx, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()

	transportFunc := func(d processor.DocumentTree) error {
		if !dochelper.DocTreeEqual(d, expectedDocTree) {
			t.Errorf("doc tree did not match up, got\n%s, \nexpected\n%s", dochelper.StringTree(d), dochelper.StringTree(expectedDocTree))
		}
		return nil
	}

	err = testSubscribe(ctx, transportFunc)
	if err != nil {
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("nats emitter Subscribe test errored = %v", err)
		}
	}
}

func testSubscribe(ctx context.Context, transportFunc func(processor.DocumentTree) error) error {
	logger := logging.FromContext(ctx)
	id := uuid.NewV4().String()

	psub, err := emitter.NewPubSub(ctx, id, emitter.SubjectNameDocCollected, emitter.DurableProcessor, emitter.BackOffTimer)
	if err != nil {
		return err
	}

	processFunc := func(d []byte) error {
		doc := processor.Document{}
		err := json.Unmarshal(d, &doc)
		if err != nil {
			fmtErr := fmt.Errorf("[processor: %s] failed unmarshal the document bytes: %w", id, err)
			logger.Error(fmtErr)
			return fmtErr
		}

		docNode := &processor.DocumentNode{
			Document: &doc,
			Children: nil,
		}

		docTree := processor.DocumentTree(docNode)
		err = transportFunc(docTree)
		if err != nil {
			fmtErr := fmt.Errorf("[processor: %s] failed transportFunc: %w", id, err)
			logger.Error(fmtErr)
			return fmtErr
		}
		logger.Infof("[processor: %s] docTree Processed: %+v", id, docTree.Document.SourceInformation)
		return nil
	}

	err = psub.GetDataFromNats(ctx, processFunc)
	if err != nil {
		return err
	}
	return nil
}
