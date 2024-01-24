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
	"errors"
	"fmt"
	"testing"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/guacsec/guac/internal/testing/dochelper"
	nats_test "github.com/guacsec/guac/internal/testing/nats"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

type mockQuery struct {
}

// NewMockQuery initializes the mockQuery to query for tests
func newMockQuery() certifier.QueryComponents {
	return &mockQuery{}
}

// GetComponents returns components for test
func (q *mockQuery) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	compChan <- []*root_package.PackageNode{&testdata.Text4ShelPackage, &testdata.SecondLevelPackage, &testdata.Log4JPackage, &testdata.RootPackage}
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
	compChan <- nil
	return nil
}

func TestCertify(t *testing.T) {
	err := RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV)
	if err != nil && !errors.Is(err, errCertifierOverwrite) {
		t.Errorf("unexpected error: %v", err)
	}

	errHandler := func(err error) bool {
		return err == nil
	}

	tests := []struct {
		name       string
		poll       bool
		query      certifier.QueryComponents
		want       []*processor.Document
		wantErr    bool
		errMessage error
	}{{
		name:  "query and generate attestation",
		poll:  false,
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
		name:  "polling - query and generate attestation",
		poll:  true,
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
		wantErr:    true,
		errMessage: context.DeadlineExceeded,
	}, {
		name:       "unknown type for collected component",
		query:      newMockUnknownQuery(),
		wantErr:    true,
		errMessage: osv.ErrOSVComponenetTypeMismatch,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ctx := logging.WithLogger(context.Background())
			if tt.poll {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 1*time.Second)
				defer cancel()
			}
			var collectedDocs []*processor.Document

			emit := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}

			err := Certify(ctx, tt.query, emit, errHandler, tt.poll, time.Second*1)
			if (err != nil) != tt.wantErr {
				t.Errorf("Certify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == context.DeadlineExceeded || err == nil {
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
	if err := jetStream.JetStreamInit(ctx); err != nil {
		t.Fatalf("unexpected error initializing jetstream: %v", err)
	}
	err = jetStream.RecreateStream(ctx)
	if err != nil {
		t.Fatalf("unexpected error recreating jetstream: %v", err)
	}
	defer jetStream.Close()

	pubsub := emitter.NewEmitterPubSub(ctx, "mem://")

	ctx = emitter.WithEmitter(ctx, pubsub)

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
	pubsub := emitter.FromContext(ctx)

	uuid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("failed to get uuid with the following error: %w", err)
	}
	uuidString := uuid.String()
	sub, err := pubsub.Subscribe(ctx, uuidString, emitter.SubjectNameDocCollected, emitter.DurableProcessor, emitter.BackOffTimer)
	if err != nil {
		return err
	}
	defer sub.CloseSubscriber(ctx)
	processFunc := func(d []byte) error {
		doc := processor.Document{}
		err := json.Unmarshal(d, &doc)
		if err != nil {
			fmtErrString := fmt.Sprintf("[processor: %s] failed unmarshal the document bytes", uuidString)
			logger.Errorf(fmtErrString+": %v", err)
			return fmt.Errorf(fmtErrString+": %w", err)
		}

		docNode := &processor.DocumentNode{
			Document: &doc,
			Children: nil,
		}

		docTree := processor.DocumentTree(docNode)
		err = transportFunc(docTree)
		if err != nil {
			fmtErrString := fmt.Sprintf("[processor: %s] failed transportFunc", uuidString)
			logger.Errorf(fmtErrString+": %v", err)
			return fmt.Errorf(fmtErrString+": %w", err)
		}
		logger.Infof("[processor: %s] docTree Processed: %+v", uuidString, docTree.Document.SourceInformation)
		return nil
	}

	err = sub.GetDataFromSubscriber(ctx, processFunc)
	if err != nil {
		return err
	}
	return nil
}
