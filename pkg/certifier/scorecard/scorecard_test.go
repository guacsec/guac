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
	mock_scorecard "github.com/guacsec/guac/internal/testing/mock"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/source"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/ossf/scorecard/v4/pkg"
)

type mockScorecard struct{}

func (m mockScorecard) GetScore(repoName, commitSHA, tag string) (*pkg.ScorecardResult, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5) // nolint:govet
	defer cancel()

	type fields struct {
		ghToken    string
		sourceNode *source.SourceNode
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
				ghToken:    "",
				sourceNode: &source.SourceNode{},
			},
			args: args{
				rootComponent: &source.SourceNode{},
				docChannel:    nil,
			},
			wantErr: true,
		},
		{
			name: "root component is nil",
			fields: fields{
				ghToken:    "",
				sourceNode: &source.SourceNode{},
			},
			args: args{
				docChannel:    make(chan *processor.Document),
				rootComponent: nil,
			},
			wantErr: true,
		},
		{
			name: "root component is not an source.SourceNode",
			fields: fields{
				ghToken:    "",
				sourceNode: &source.SourceNode{},
			},
			args: args{
				docChannel:    make(chan *processor.Document),
				rootComponent: "",
			},
			wantErr: true,
		},
		{
			name: "SourceNode.Digest error",
			fields: fields{
				ghToken:    "",
				sourceNode: &source.SourceNode{},
			},
			args: args{
				docChannel:    make(chan *processor.Document),
				rootComponent: &source.SourceNode{},
			},
			wantErr: true,
		},
		{
			name: "repo name is empty",
			fields: fields{
				ghToken:    "",
				sourceNode: &source.SourceNode{},
			},
			args: args{
				docChannel: make(chan *processor.Document),
				rootComponent: &source.SourceNode{
					Commit: "test",
				},
			},
			wantErr: true,
		},
		{
			name: "scorecard getScore returns error",
			fields: fields{
				ghToken:    "",
				sourceNode: &source.SourceNode{},
			},
			args: args{
				docChannel: make(chan *processor.Document),
				rootComponent: &source.SourceNode{
					Commit: "test",
					Repo:   "test",
				},
			},
			getScoreShouldReturnErr: true,
			wantErr:                 true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			sc := mock_scorecard.NewMockScorecard(ctrl)
			sc.EXPECT().GetScore(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(a, b, c string) (*pkg.ScorecardResult, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // nolint:govet
	defer cancel()

	ctrl := gomock.NewController(t)
	scMock := mock_scorecard.NewMockScorecard(ctrl)
	scMock.EXPECT().GetScore(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(a, b, c string) (*pkg.ScorecardResult, error) {
			return &pkg.ScorecardResult{}, nil
		}).AnyTimes()

	// Create a mock source.SourceNode to use as input
	source := &source.SourceNode{
		Repo:   "myrepo",
		Commit: "abc123",
		Tag:    "",
	}

	// Create a mock Scorecard instance to use
	sc := scorecard{
		scorecard: scMock,
		ghToken:   "test",
	}

	// TODO: Use go routines to test the channel
	// valid input
	docChannel := make(chan *processor.Document, 2)

	err := sc.CertifyComponent(ctx, source, docChannel)
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
