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

	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/pkg/assembler"
	mocks "github.com/guacsec/guac/pkg/certifier/scorecard/mock"
	"github.com/guacsec/guac/pkg/handler/processor"

	"github.com/guacsec/guac/pkg/certifier"
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

			got, err := NewScorecard(test.sc)
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
		{
			name: "default case",
			fields: fields{
				ghToken:  "",
				artifact: &assembler.ArtifactNode{},
			},
			args: args{
				ctx:           context.Background(),
				docChannel:    make(chan *processor.Document),
				rootComponent: &assembler.ArtifactNode{},
			},
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
				artifact:  test.fields.artifact,
			}
			if err := s.CertifyComponent(test.args.ctx, test.args.rootComponent, test.args.docChannel); (err != nil) != test.wantErr {
				t.Errorf("CertifyComponent() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
