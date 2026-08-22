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

	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/source"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/ossf/scorecard/v5/checks"
	scpkg "github.com/ossf/scorecard/v5/pkg/scorecard"
	"go.uber.org/mock/gomock"
)

type mockScorecard struct{}

func (m mockScorecard) GetScore(repoName, commitSHA, tag string) (*scpkg.Result, error) {
	return &scpkg.Result{}, nil
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
			wantErr:       false,
			want:          &scorecard{scorecard: mockScorecard{}, ghToken: ""},
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
			sc := mocks.NewMockScorecard(ctrl)
			sc.EXPECT().GetScore(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(a, b, c string) (*scpkg.Result, error) {
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
	scMock := mocks.NewMockScorecard(ctrl)
	scMock.EXPECT().GetScore(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(a, b, c string) (*scpkg.Result, error) {
			return &scpkg.Result{}, nil
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

func Test_scorecardRunner_supportedChecks(t *testing.T) {
	runner := scorecardRunner{ctx: context.Background()}
	input := []string{checks.CheckContributors, checks.CheckLicense}

	tests := []struct {
		name      string
		commitSHA string
		want      []string
	}{
		{name: "empty commit keeps every check", commitSHA: "", want: input},
		{name: "HEAD keeps every check", commitSHA: "HEAD", want: input},
		{name: "pinned commit drops unsupported checks", commitSHA: "98316298749fdd62d3cc99423baec45ae11af662", want: []string{checks.CheckLicense}},
		{name: "branch name drops unsupported checks", commitSHA: "main", want: []string{checks.CheckLicense}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := runner.supportedChecks(input, test.commitSHA); !reflect.DeepEqual(got, test.want) {
				t.Errorf("supportedChecks() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCertifyComponentTaggedSourceLabel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // nolint:govet
	defer cancel()

	ctrl := gomock.NewController(t)
	scMock := mocks.NewMockScorecard(ctrl)
	scMock.EXPECT().GetScore(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_, _, _ string) (*scpkg.Result, error) {
			return &scpkg.Result{}, nil
		}).AnyTimes()

	sc := scorecard{scorecard: scMock, ghToken: "test"}
	docChannel := make(chan *processor.Document, 2)

	err := sc.CertifyComponent(ctx, &source.SourceNode{Repo: "myrepo", Tag: "v1.0.0"}, docChannel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	res := <-docChannel
	if want := "myrepo@v1.0.0"; res.SourceInformation.Source != want {
		t.Errorf("SourceInformation.Source = %q, want %q", res.SourceInformation.Source, want)
	}
}

func TestSplitOwnerRepo(t *testing.T) {
	tests := []struct {
		name      string
		repoName  string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{name: "prefixed", repoName: "github.com/ossf/scorecard", wantOwner: "ossf", wantRepo: "scorecard"},
		{name: "unprefixed", repoName: "ossf/scorecard", wantOwner: "ossf", wantRepo: "scorecard"},
		{name: "owner only", repoName: "github.com/ossf", wantErr: true},
		{name: "extra path segment", repoName: "github.com/ossf/scorecard/v5", wantErr: true},
		{name: "empty repo", repoName: "github.com/ossf/", wantErr: true},
		{name: "empty", repoName: "", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owner, repo, err := splitOwnerRepo(test.repoName)
			if (err != nil) != test.wantErr {
				t.Fatalf("splitOwnerRepo() error = %v, wantErr %v", err, test.wantErr)
			}
			if err != nil {
				return
			}
			if owner != test.wantOwner || repo != test.wantRepo {
				t.Errorf("splitOwnerRepo() = %q, %q, want %q, %q", owner, repo, test.wantOwner, test.wantRepo)
			}
		})
	}
}

func stubTagCommit(t *testing.T, fn func(ctx context.Context, owner, repo, tag string) (string, error)) {
	t.Helper()
	orig := tagCommit
	tagCommit = fn
	t.Cleanup(func() { tagCommit = orig })
}

func Test_scorecardRunner_commitForTag(t *testing.T) {
	const wantSHA = "98316298749fdd62d3cc99423baec45ae11af662"
	runner := scorecardRunner{ctx: context.Background()}

	t.Run("resolves tag to commit", func(t *testing.T) {
		var gotOwner, gotRepo, gotTag string
		stubTagCommit(t, func(_ context.Context, owner, repo, tag string) (string, error) {
			gotOwner, gotRepo, gotTag = owner, repo, tag
			return wantSHA, nil
		})

		got, err := runner.commitForTag("github.com/ossf/scorecard", "v4.10.4")
		if err != nil {
			t.Fatalf("commitForTag() error = %v", err)
		}
		if got != wantSHA {
			t.Errorf("commitForTag() = %q, want %q", got, wantSHA)
		}
		if gotOwner != "ossf" || gotRepo != "scorecard" || gotTag != "v4.10.4" {
			t.Errorf("resolver called with %q, %q, %q; want ossf, scorecard, v4.10.4", gotOwner, gotRepo, gotTag)
		}
	})

	t.Run("propagates resolver failure", func(t *testing.T) {
		stubTagCommit(t, func(_ context.Context, _, _, _ string) (string, error) {
			return "", fmt.Errorf("404 tag not found")
		})
		if _, err := runner.commitForTag("github.com/ossf/scorecard", "v9.9.9"); err == nil {
			t.Fatal("commitForTag() error = nil, want a resolution failure")
		}
	})

	t.Run("rejects empty commit", func(t *testing.T) {
		stubTagCommit(t, func(_ context.Context, _, _, _ string) (string, error) {
			return "", nil
		})
		if _, err := runner.commitForTag("github.com/ossf/scorecard", "v4.10.4"); err == nil {
			t.Fatal("commitForTag() error = nil, want an empty-SHA failure")
		}
	})

	t.Run("rejects unparseable repo", func(t *testing.T) {
		stubTagCommit(t, func(_ context.Context, _, _, _ string) (string, error) {
			t.Fatal("resolver called for an unparseable repo name")
			return "", nil
		})
		if _, err := runner.commitForTag("github.com/ossf", "v4.10.4"); err == nil {
			t.Fatal("commitForTag() error = nil, want a parse failure")
		}
	})
}
