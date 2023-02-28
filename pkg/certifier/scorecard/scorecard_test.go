//
// Copyright 2023 The GUAC Authors.
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

package scorecard

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	mocks "github.com/guacsec/guac/internal/testing/mock"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/ossf/scorecard/v4/pkg"
)

type mockScorecard struct{}

func (m mockScorecard) GetScore(repoName, commitSHA string) (*pkg.ScorecardResult, error) {
	return &pkg.ScorecardResult{}, nil
}

func TestNewScorecard(t *testing.T) {
	tests := []struct {
		name          string
		sc            Scorecard
		client        graphdb.Client
		want          certifier.Certifier
		wantErr       bool
		authToken     string
		wantAuthToken bool
	}{
		{
			name:    "scorecard is nil",
			wantErr: true,
		},
		{
			name:          "Auth token is set",
			sc:            mockScorecard{},
			want:          &scorecard{scorecard: mockScorecard{}, ghToken: "test"},
			authToken:     "test",
			wantAuthToken: true,
		},
		{
			name:          "Auth token is empty",
			sc:            mockScorecard{},
			authToken:     "",
			wantAuthToken: true,
			wantErr:       true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.wantAuthToken {
				t.Setenv("GITHUB_AUTH_TOKEN", test.authToken)
			}

			got, err := NewScorecardCertifier(test.sc)
			if (err != nil) != test.wantErr {
				t.Errorf("NewScorecardCertifier() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("NewScorecardCertifier() got = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_CertifyComponent(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), time.Second) // nolint:govet

	type fields struct {
		ghToken  string
		artifact *assembler.ArtifactNode
	}
	type args struct {
		rootComponent interface{}
		docChannel    chan<- *processor.Document
	}
	tests := []struct {
		name                    string
		fields                  fields
		args                    args
		getScoreShouldReturnErr bool
		wantErr                 bool
	}{
		{
			name: "doc chan is nil",
			fields: fields{
				ghToken:  "",
				artifact: &assembler.ArtifactNode{},
			},
			args: args{
				rootComponent: &assembler.ArtifactNode{},
				docChannel:    nil,
			},
			wantErr: true,
		},
		{
			name: "root component is nil",
			fields: fields{
				ghToken:  "",
				artifact: &assembler.ArtifactNode{},
			},
			args: args{
				docChannel:    make(chan *processor.Document),
				rootComponent: nil,
			},
			wantErr: true,
		},
		{
			name: "root component is not an artifact node",
			fields: fields{
				ghToken:  "",
				artifact: &assembler.ArtifactNode{},
			},
			args: args{
				docChannel:    make(chan *processor.Document),
				rootComponent: "",
			},
			wantErr: true,
		},
		{
			name: "artifactNode.Digest error",
			fields: fields{
				ghToken:  "",
				artifact: &assembler.ArtifactNode{},
			},
			args: args{
				docChannel:    make(chan *processor.Document),
				rootComponent: &assembler.ArtifactNode{},
			},
			wantErr: true,
		},
		{
			name: "repo name is empty",
			fields: fields{
				ghToken:  "",
				artifact: &assembler.ArtifactNode{},
			},
			args: args{
				docChannel: make(chan *processor.Document),
				rootComponent: &assembler.ArtifactNode{
					Digest: "test",
				},
			},
			wantErr: true,
		},
		{
			name: "scorecard getScore returns error",
			fields: fields{
				ghToken:  "",
				artifact: &assembler.ArtifactNode{},
			},
			args: args{
				docChannel: make(chan *processor.Document),
				rootComponent: &assembler.ArtifactNode{
					Digest: "test",
					Name:   "test",
				},
			},
			getScoreShouldReturnErr: true,
			wantErr:                 true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			sc := mocks.NewMockScorecard(ctrl)
			sc.EXPECT().GetScore(gomock.Any(), gomock.Any()).
				DoAndReturn(func(a, b string) (*pkg.ScorecardResult, error) {
					if test.getScoreShouldReturnErr {
						return nil, fmt.Errorf("error")
					}
					return nil, nil
				}).AnyTimes()

			s := scorecard{
				scorecard: sc,
				ghToken:   test.fields.ghToken,
			}
			if err := s.CertifyComponent(ctx, test.args.rootComponent, test.args.docChannel); (err != nil) != test.wantErr {
				t.Errorf("CertifyComponent() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestCertifyComponentDefaultCase(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second) // nolint:govet

	ctrl := gomock.NewController(t)
	scMock := mocks.NewMockScorecard(ctrl)
	scMock.EXPECT().GetScore(gomock.Any(), gomock.Any()).
		DoAndReturn(func(a, b string) (*pkg.ScorecardResult, error) {
			return &pkg.ScorecardResult{}, nil
		}).AnyTimes()

	// Create a mock ArtifactNode to use as input
	artifact := &assembler.ArtifactNode{
		Name:   "git+myrepo",
		Digest: "abc123",
	}

	// Create a mock Scorecard instance to use
	sc := scorecard{
		scorecard: scMock,
		ghToken:   "test",
	}

	// valid input
	docChannel := make(chan *processor.Document, 2)

	err := sc.CertifyComponent(ctx, artifact, docChannel)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	res := <-docChannel
	if res.Type != processor.DocumentScorecard {
		t.Errorf("unexpected document type: %v", res.Type)
	}
	if res.Format != processor.FormatJSON {
		t.Errorf("unexpected document format: %v", res.Format)
	}
	if len(res.Blob) < 100 {
		// the test scorecard result is less than 100 bytes
		t.Errorf("unexpected document blob size: %v", len(res.Blob))
	}
}
