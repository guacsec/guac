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
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/ossf/scorecard/v4/checker"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/pkg/assembler"
	mocks "github.com/guacsec/guac/pkg/certifier/scorecard/mock"
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

			got, err := NewScorecard(test.sc, test.client)
			if (err != nil) != test.wantErr {
				t.Errorf("NewScorecard() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("NewScorecard() got = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_scorecard_CertifyComponent(t *testing.T) {
	type fields struct {
		ghToken  string
		artifact *assembler.ArtifactNode
	}
	type args struct {
		ctx           context.Context
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
				ctx:           context.Background(),
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
				ctx:           context.Background(),
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
				ctx:           context.Background(),
				docChannel:    make(chan *processor.Document),
				rootComponent: "",
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
				ctx:           context.Background(),
				docChannel:    make(chan *processor.Document),
				rootComponent: &assembler.ArtifactNode{},
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
			if err := s.CertifyComponent(test.args.ctx, test.args.rootComponent, test.args.docChannel); (err != nil) != test.wantErr {
				t.Errorf("CertifyComponent() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestCertifyComponent(t *testing.T) {
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	scMock := mocks.NewMockScorecard(ctrl)
	scMock.EXPECT().GetScore(gomock.Any(), gomock.Any()).
		DoAndReturn(func(a, b string) (*pkg.ScorecardResult, error) {
			return &pkg.ScorecardResult{
				Repo: pkg.RepoInfo{
					Name:      "test",
					CommitSHA: "test",
				},
				Date: time.Now(),
				Scorecard: pkg.ScorecardInfo{
					Version:   "test",
					CommitSHA: "test",
				},
				Checks: []checker.CheckResult{
					checker.CheckResult{
						Name:    "Maintained",
						Version: 10,
						Error:   nil,
						Details: []checker.CheckDetail{
							{
								Msg:  checker.LogMessage{},
								Type: 0,
							},
						},
						Score:  10,
						Reason: "test",
					},
				},
				RawResults: checker.RawResults{},
				Metadata:   []string{},
			}, nil
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
		client:    nil,
	}

	// Test case 1: valid input
	docChannel := make(chan *processor.Document, 2)

	err := sc.CertifyComponent(ctx, artifact, docChannel)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	res := <-docChannel
	if res.Type != processor.DocumentScorecard {
		t.Errorf("unexpected document type: %v", res.Type)
	}
	if res.Format != processor.FormatUnknown {
		t.Errorf("unexpected document format: %v", res.Format)
	}
	if len(res.Blob) < 100 {
		// the test scorecard result is less than 100 bytes
		t.Errorf("unexpected document blob size: %v", len(res.Blob))
	}

	// Test case 2: nil docChannel
	err = sc.CertifyComponent(ctx, artifact, nil)
	if err == nil {
		t.Error("expected error for nil docChannel")
	}

	// Test case 3: nil rootComponent
	err = sc.CertifyComponent(ctx, nil, docChannel)
	if err == nil {
		t.Error("expected error for nil rootComponent")
	}

	// Test case 4: invalid rootComponent type
	err = sc.CertifyComponent(ctx, "not an ArtifactNode", docChannel)
	if err != ErrArtifactNodeTypeMismatch {
		t.Errorf("expected ErrArtifactNodeTypeMismatch, but got: %v", err)
	}
}
