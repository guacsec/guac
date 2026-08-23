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
	"slices"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/source"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks"
	scpkg "github.com/ossf/scorecard/v5/pkg/scorecard"
	"github.com/ossf/scorecard/v5/policy"
	"go.uber.org/mock/gomock"
)

const pinnedSHA = "98316298749fdd62d3cc99423baec45ae11af662"

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
	input := []string{checks.CheckContributors, checks.CheckLicense, checks.CheckMaintained}

	tests := []struct {
		name      string
		commitSHA string
		want      []string
	}{
		{name: "empty commit keeps every check", commitSHA: "", want: input},
		{name: "HEAD keeps every check", commitSHA: "HEAD", want: input},
		{name: "lowercase head keeps every check", commitSHA: "head", want: input},
		{name: "pinned SHA drops unsupported checks", commitSHA: pinnedSHA, want: []string{checks.CheckLicense}},
		{name: "branch name drops unsupported checks", commitSHA: "main", want: []string{checks.CheckLicense}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := runner.supportedChecks(input, test.commitSHA); !slices.Equal(got, test.want) {
				t.Errorf("supportedChecks() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_scorecardRunner_supportedChecksPassPolicyGate(t *testing.T) {
	runner := scorecardRunner{ctx: context.Background()}
	filtered := runner.supportedChecks(defaultCheckNames(), pinnedSHA)

	if len(filtered) == 0 {
		t.Fatal("supportedChecks() returned no checks for a pinned commit")
	}
	if _, err := policy.GetEnabled(nil, filtered, []checker.RequestType{checker.CommitBased}); err != nil {
		t.Errorf("policy.GetEnabled() error = %v, want nil", err)
	}
}

func Test_defaultCheckNamesPassPolicyGateAtHead(t *testing.T) {
	if _, err := policy.GetEnabled(nil, defaultCheckNames(), nil); err != nil {
		t.Errorf("policy.GetEnabled() error = %v, want nil", err)
	}
}

func TestCertifyComponentSourceLabel(t *testing.T) {
	tests := []struct {
		name   string
		commit string
		tag    string
		want   string
	}{
		{name: "commit only", commit: pinnedSHA, want: "myrepo@" + pinnedSHA},
		{name: "commit wins over tag", commit: pinnedSHA, tag: "v1.0.0", want: "myrepo@" + pinnedSHA},
		{name: "tag replaces HEAD", commit: "HEAD", tag: "v1.0.0", want: "myrepo@v1.0.0"},
		{name: "tag replaces empty commit", tag: "v1.0.0", want: "myrepo@v1.0.0"},
		{name: "neither falls back to HEAD", want: "myrepo@HEAD"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // nolint:govet
			defer cancel()

			scMock := mocks.NewMockScorecard(gomock.NewController(t))
			scMock.EXPECT().GetScore(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&scpkg.Result{}, nil).AnyTimes()

			sc := scorecard{scorecard: scMock, ghToken: "test"}
			docChannel := make(chan *processor.Document, 1)

			node := &source.SourceNode{Repo: "myrepo", Commit: test.commit, Tag: test.tag}
			if err := sc.CertifyComponent(ctx, node, docChannel); err != nil {
				t.Fatalf("CertifyComponent() error = %v", err)
			}

			if got := (<-docChannel).SourceInformation.Source; got != test.want {
				t.Errorf("SourceInformation.Source = %q, want %q", got, test.want)
			}
		})
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
		{name: "empty owner", repoName: "github.com//scorecard", wantErr: true},
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

func Test_scorecardRunner_commitForTag(t *testing.T) {
	t.Run("resolves tag to commit", func(t *testing.T) {
		var gotOwner, gotRepo, gotTag string
		runner := scorecardRunner{ctx: context.Background(), resolveTag: func(_ context.Context, owner, repo, tag string) (string, error) {
			gotOwner, gotRepo, gotTag = owner, repo, tag
			return pinnedSHA, nil
		}}

		got, err := runner.commitForTag("github.com/ossf/scorecard", "v4.10.4")
		if err != nil {
			t.Fatalf("commitForTag() error = %v", err)
		}
		if got != pinnedSHA {
			t.Errorf("commitForTag() = %q, want %q", got, pinnedSHA)
		}
		if gotOwner != "ossf" || gotRepo != "scorecard" || gotTag != "v4.10.4" {
			t.Errorf("resolver called with %q, %q, %q; want ossf, scorecard, v4.10.4", gotOwner, gotRepo, gotTag)
		}
	})

	t.Run("propagates resolver failure", func(t *testing.T) {
		runner := scorecardRunner{ctx: context.Background(), resolveTag: func(_ context.Context, _, _, _ string) (string, error) {
			return "", fmt.Errorf("404 tag not found")
		}}
		if _, err := runner.commitForTag("github.com/ossf/scorecard", "v9.9.9"); err == nil {
			t.Fatal("commitForTag() error = nil, want a resolution failure")
		}
	})

	// An empty SHA would be passed to scorecard as an empty commit, which it
	// reads as a pinned empty revision rather than HEAD.
	t.Run("rejects empty commit", func(t *testing.T) {
		runner := scorecardRunner{ctx: context.Background(), resolveTag: func(_ context.Context, _, _, _ string) (string, error) {
			return "", nil
		}}
		if _, err := runner.commitForTag("github.com/ossf/scorecard", "v4.10.4"); err == nil {
			t.Fatal("commitForTag() error = nil, want an empty-SHA failure")
		}
	})

	t.Run("rejects unparseable repo", func(t *testing.T) {
		runner := scorecardRunner{ctx: context.Background(), resolveTag: func(_ context.Context, _, _, _ string) (string, error) {
			t.Fatal("resolver called for an unparseable repo name")
			return "", nil
		}}
		if _, err := runner.commitForTag("github.com/ossf", "v4.10.4"); err == nil {
			t.Fatal("commitForTag() error = nil, want a parse failure")
		}
	})
}
