//
// Copyright 2022 The AFF Authors.
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

package verifier

import (
	"reflect"
	"testing"

	"github.com/artifact-ff/artifact-ff/pkg/ingestor/processor"
	"github.com/artifact-ff/artifact-ff/pkg/key"
	"github.com/artifact-ff/artifact-ff/pkg/key/inmemory"
	"github.com/artifact-ff/artifact-ff/pkg/testutils"
	"github.com/artifact-ff/artifact-ff/pkg/verifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func TestSigstoreVerifier_Verify(t *testing.T) {
	// Doc based on https://github.com/secure-systems-lab/dsse/blob/31569a75dbe2b956f27b510394f5ff82a9958ec2/protocol.md
	// I had to manually generate the keyid based on the ECDSA key
	d := &processor.Document{
		Blob: []byte(`
		{
			"payload": "aGVsbG8gd29ybGQ=",
			"payloadType": "http://example.com/HelloWorld",
			"signatures": [
				{
					"keyid": "4205d7b430cb1c84e6db1a43cc3e747e78702a0d56a43174ee17158aa92e9f5b"
					"sig": "A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA=="
				}
			]
		}`),
		Type:   processor.DocumentDSSE,
		Format: processor.FormatJSON,
		TrustInformation: processor.TrustInformation{
			DSSE: &dsse.Envelope{
				PayloadType: "http://example.com/HelloWorld",
				Payload:     "aGVsbG8gd29ybGQ=",
				Signatures: []dsse.Signature{{
					KeyID: "4205d7b430cb1c84e6db1a43cc3e747e78702a0d56a43174ee17158aa92e9f5b",
					Sig:   "A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA==",
				}},
			},
			IssuerUri: new(string),
		},
		SourceInformation: processor.SourceInformation{},
	}
	type fields struct {
		keyProvider key.KeyProvider
	}
	type args struct {
		i *processor.Document
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []verifier.VerifiedKey
		wantErr bool
	}{
		{
			name: "Test Verify Document",
			fields: fields{
				keyProvider: inmemory.New(
					key.KeyMap{
						"4205d7b430cb1c84e6db1a43cc3e747e78702a0d56a43174ee17158aa92e9f5b": testutils.GetDSSEExampleKey(),
					},
				),
			},
			args: args{
				i: d,
			},
			want: []verifier.VerifiedKey{
				{
					Key: testutils.GetDSSEExampleKey(),
					ID:  "4205d7b430cb1c84e6db1a43cc3e747e78702a0d56a43174ee17158aa92e9f5b",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &SigstoreVerifier{
				keyProvider: tt.fields.keyProvider,
			}
			got, err := d.Verify(tt.args.i)
			if (err != nil) != tt.wantErr {
				t.Errorf("SigstoreVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SigstoreVerifier.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
