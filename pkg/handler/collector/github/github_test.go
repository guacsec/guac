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

package github

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/client"
	"github.com/guacsec/guac/internal/client/githubclient"
	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type MockGithubClient struct {
}

const (
	mockTag               = "mockTag"
	mockCommit            = "mockCommit"
	mockReleaseUrlLatest  = "https://github.com/mock/repo/releases"
	mockReleaseUrlWithTag = "https://github.com/mock/repo/releases/v1"
	mockAssetUrl          = "https://github.com/mock/repo/releases/releaseAsset.json"
)

func mockReleaseAsset() client.ReleaseAsset {
	return client.ReleaseAsset{
		Name: "releaseAsset.json",
		URL:  "https://github.com/mock/repo/releases/releaseAsset.json",
	}
}

func mockReleaseAssetContent() client.ReleaseAssetContent {
	return client.ReleaseAssetContent{
		Name:  "releaseAsset.json",
		Bytes: testdata.Ite6Payload,
	}
}

// TODO(mlieberman85): This should be pulled into testing utils.
func toDataSource(githubValues map[string][]datasource.Source) datasource.CollectSource {
	ds, err := inmemsource.NewInmemDataSources(&datasource.DataSources{
		GithubReleaseDataSources: githubValues["github"],
		GitDataSources:           githubValues["git"],
	})
	if err != nil {
		panic(err)
	}
	return ds
}

func mockDataSource() datasource.CollectSource {
	githubValues := map[string][]datasource.Source{
		"github": {
			{
				Value: mockReleaseUrlLatest,
			},
			{
				Value: mockReleaseUrlWithTag,
			},
		},
	}

	return toDataSource(githubValues)
}

func mockRepoToReleaseTagsLatest() map[client.Repo][]TagOrLatest {
	return map[client.Repo][]TagOrLatest{
		{
			Owner: "mock",
			Repo:  "repo",
		}: {
			Latest,
		},
	}
}

func mockRepoToReleaseTagsWithTag() map[client.Repo][]TagOrLatest {
	return map[client.Repo][]TagOrLatest{
		{
			Owner: "mock",
			Repo:  "repo",
		}: {
			"v1",
		},
	}
}

// GetLatestRelease fetches the latest release for a repo
func (m *MockGithubClient) GetLatestRelease(ctx context.Context, owner string, repo string) (*client.Release, error) {
	r := &client.Release{
		Tag:    mockTag,
		Commit: mockCommit,
		Assets: []client.ReleaseAsset{mockReleaseAsset()},
	}

	return r, nil
}

// GetCommitSHA1 fetches the commit SHA in a repo based on a tag, branch head, or other ref.
// NOTE: Github release 2022-11-28 and similar server returns a commitish for a release.
// The release commitish can be a commit, branch name, or a tag.
// We need to resolve it to a commit.
func (m *MockGithubClient) GetCommitSHA1(ctx context.Context, owner string, repo string, ref string) (string, error) {
	return mockCommit, nil
}

// GetReleaseByTagSlices fetches metadata regarding releases for a given tag. If the tag is the empty string,
// it should just return the latest.
func (m *MockGithubClient) GetReleaseByTag(ctx context.Context, owner string, repo string, tag string) (*client.Release, error) {
	r := &client.Release{
		Tag:    mockTag,
		Commit: mockCommit,
		Assets: []client.ReleaseAsset{mockReleaseAsset()},
	}

	return r, nil
}

// GetReleaseAsset fetches the content of a release asset, e.g. artifacts, metadata documents, etc.
func (m *MockGithubClient) GetReleaseAsset(asset client.ReleaseAsset) (*client.ReleaseAssetContent, error) {
	rac := mockReleaseAssetContent()
	return &rac, nil
}

func TestNewGithubCollector(t *testing.T) {
	mockClient := &MockGithubClient{}
	mockData := mockDataSource()
	mockLatest := mockRepoToReleaseTagsLatest()
	mockTag := mockRepoToReleaseTagsWithTag()

	type args struct {
		opts []Opt
	}
	tests := []struct {
		name       string
		args       args
		want       *githubCollector
		wantErr    bool
		errMessage error
	}{
		{
			name: "with datasource",
			args: args{
				opts: []Opt{
					WithCollectDataSource(mockData),
					WithClient(mockClient),
				},
			},
			want: &githubCollector{
				poll:              false,
				interval:          0,
				client:            mockClient,
				repoToReleaseTags: map[client.Repo][]TagOrLatest{},
				assetSuffixes:     defaultAssetSuffixes(),
				collectDataSource: mockData,
			},
			wantErr: false,
		},
		{
			name: "with repo to release tags latest release",
			args: args{
				opts: []Opt{
					WithRepoToReleaseTags(mockLatest),
					WithClient(mockClient),
				},
			},
			want: &githubCollector{
				poll:              false,
				interval:          0,
				client:            mockClient,
				repoToReleaseTags: mockLatest,
				assetSuffixes:     defaultAssetSuffixes(),
				collectDataSource: nil,
			},
			wantErr: false,
		},
		{
			name: "with repo to release tags with tag",
			args: args{
				opts: []Opt{
					WithRepoToReleaseTags(mockTag),
					WithClient(mockClient),
				},
			},
			want: &githubCollector{
				poll:              false,
				interval:          0,
				client:            mockClient,
				repoToReleaseTags: mockTag,
				assetSuffixes:     defaultAssetSuffixes(),
				collectDataSource: nil,
			},
			wantErr: false,
		},
		{
			name: "incomplete options",
			args: args{
				opts: []Opt{},
			},
			want:       nil,
			wantErr:    true,
			errMessage: errors.New("no github client provided for collector"),
		},
		{
			name: "empty asset suffixes",
			args: args{
				opts: []Opt{
					WithRepoToReleaseTags(mockTag),
					WithClient(mockClient),
					WithAssetSuffixes([]string{}),
				},
			},
			want:       nil,
			wantErr:    true,
			errMessage: errors.New("no asset suffixes for github collector"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewGithubCollector(tt.args.opts...)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("NewGithubCollector() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.errMessage.Error()) {
					t.Errorf("NewGithubCollector() error = %v, wantErr %v", err, tt.errMessage)
					return
				}
			} else {
				if tt.wantErr {
					t.Errorf("NewGithubCollector() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewGithubCollector() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_githubCollector_RetrieveArtifacts(t *testing.T) {
	mockClient := &MockGithubClient{}
	mockData := mockDataSource()

	type fields struct {
		poll              bool
		interval          time.Duration
		client            githubclient.GithubClient
		repoToReleaseTags map[client.Repo][]TagOrLatest
		assetSuffixes     []string
		collectDataSource datasource.CollectSource
	}
	tests := []struct {
		name       string
		fields     fields
		want       []*processor.Document
		wantErr    bool
		errMessage error
	}{
		{
			name: "get from datasource",
			fields: fields{
				poll:              false,
				interval:          0,
				client:            mockClient,
				repoToReleaseTags: map[client.Repo][]TagOrLatest{},
				assetSuffixes:     []string{".json"},
				collectDataSource: mockData,
			},
			want: []*processor.Document{
				{
					Blob:   testdata.Ite6Payload,
					Type:   processor.DocumentUnknown,
					Format: processor.FormatUnknown,
					SourceInformation: processor.SourceInformation{
						Collector: GithubCollector,
						Source:    mockReleaseAsset().URL,
					},
				},
				{
					Blob:   testdata.Ite6Payload,
					Type:   processor.DocumentUnknown,
					Format: processor.FormatUnknown,
					SourceInformation: processor.SourceInformation{
						Collector: GithubCollector,
						Source:    mockReleaseAsset().URL,
					},
				},
			},
			wantErr:    false,
			errMessage: nil,
		},
		{
			name: "get from passed in repo to release tags",
			fields: fields{
				poll:              false,
				interval:          0,
				client:            mockClient,
				repoToReleaseTags: mockRepoToReleaseTagsLatest(),
				assetSuffixes:     []string{".json"},
				collectDataSource: nil,
			},
			want: []*processor.Document{
				{
					Blob:   testdata.Ite6Payload,
					Type:   processor.DocumentUnknown,
					Format: processor.FormatUnknown,
					SourceInformation: processor.SourceInformation{
						Collector: GithubCollector,
						Source:    mockReleaseAsset().URL,
					},
				},
			},
			wantErr:    false,
			errMessage: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &githubCollector{
				poll:              tt.fields.poll,
				interval:          tt.fields.interval,
				client:            tt.fields.client,
				repoToReleaseTags: tt.fields.repoToReleaseTags,
				assetSuffixes:     tt.fields.assetSuffixes,
				collectDataSource: tt.fields.collectDataSource,
			}
			ctx := context.Background()
			var cancel context.CancelFunc

			if tt.fields.poll {
				ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
			}

			var err error
			docChan := make(chan *processor.Document, 1)
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- g.RetrieveArtifacts(ctx, docChan)
			}()
			numCollectors := 1
			collectorsDone := 0

			collectedDocs := []*processor.Document{}

			for collectorsDone < numCollectors {
				select {
				case d := <-docChan:
					collectedDocs = append(collectedDocs, d)
				case err = <-errChan:
					if err != nil {
						if !tt.wantErr {
							if err := g.RetrieveArtifacts(ctx, docChan); (err != nil) != tt.wantErr {
								t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
							}
						}
					}
					collectorsDone += 1
				}
			}
			// Drain anything left in document channel
			for len(docChan) > 0 {
				d := <-docChan
				collectedDocs = append(collectedDocs, d)
			}
			if err == nil {
				for i := range collectedDocs {
					result := dochelper.DocTreeEqual(dochelper.DocNode(collectedDocs[i]), dochelper.DocNode(tt.want[i]))
					if !result {
						t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
					}
				}

				if g.Type() != GithubCollector {
					t.Errorf("g.Type() = %s, want %s", g.Type(), GithubCollector)
				}
			}
		})
	}
}

func Test_githubCollector_populateRepoToReleaseTags(t *testing.T) {
	mockData := mockDataSource()
	mockBadData := toDataSource(map[string][]datasource.Source{
		"github": {
			{
				Value: "https://bad_url",
			},
			{
				Value: mockReleaseUrlLatest,
			},
		},
	})

	type fields struct {
		poll              bool
		interval          time.Duration
		client            githubclient.GithubClient
		repoToReleaseTags map[client.Repo][]TagOrLatest
		assetSuffixes     []string
		collectDataSource datasource.CollectSource
	}
	tests := []struct {
		name    string
		fields  fields
		want    map[client.Repo][]TagOrLatest
		wantErr bool
	}{
		{
			name: "with data source",
			fields: fields{
				poll:              false,
				interval:          0,
				client:            nil,
				repoToReleaseTags: map[client.Repo][]TagOrLatest{},
				assetSuffixes:     []string{},
				collectDataSource: mockData,
			},
			want: map[client.Repo][]TagOrLatest{
				{
					Owner: "mock",
					Repo:  "repo",
				}: {
					Latest,
					"v1",
				},
			},
			wantErr: false,
		},
		{
			name: "without data source",
			fields: fields{
				poll:              false,
				interval:          0,
				client:            nil,
				repoToReleaseTags: map[client.Repo][]TagOrLatest{},
				assetSuffixes:     []string{},
				collectDataSource: nil,
			},
			want:    map[client.Repo][]TagOrLatest{},
			wantErr: false,
		},
		{
			name: "data source with bad url",
			fields: fields{
				poll:              false,
				interval:          0,
				client:            nil,
				repoToReleaseTags: map[client.Repo][]TagOrLatest{},
				assetSuffixes:     []string{},
				collectDataSource: mockBadData,
			},
			want: map[client.Repo][]TagOrLatest{
				{
					Owner: "mock",
					Repo:  "repo",
				}: {
					Latest,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			g := &githubCollector{
				poll:              tt.fields.poll,
				interval:          tt.fields.interval,
				client:            tt.fields.client,
				repoToReleaseTags: tt.fields.repoToReleaseTags,
				assetSuffixes:     tt.fields.assetSuffixes,
				collectDataSource: tt.fields.collectDataSource,
			}
			if err := g.populateRepoToReleaseTags(ctx); (err != nil) != tt.wantErr {
				t.Errorf("githubCollector.populateRepoToReleaseTags() error = %v, wantErr %v", err, tt.wantErr)
			}
			got := tt.fields.repoToReleaseTags
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("githubCollector.populateRepoToReleaseTags() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkSuffixes(t *testing.T) {
	type args struct {
		name     string
		suffixes []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "suffix included",
			args: args{
				name:     ".x",
				suffixes: []string{".y", ".z", ".x", ".a"},
			},
			want: true,
		},
		{
			name: "suffix not included",
			args: args{
				name:     ".x",
				suffixes: []string{".a", ".b", ".c", ".d"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkSuffixes(tt.args.name, tt.args.suffixes); got != tt.want {
				t.Errorf("checkSuffixes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseGithubReleaseDataSource(t *testing.T) {
	type args struct {
		source datasource.Source
	}
	tests := []struct {
		name       string
		args       args
		want       *client.Repo
		want1      TagOrLatest
		wantErr    bool
		errMessage error
	}{
		{
			name: "parse valid latest github url",
			args: args{
				source: datasource.Source{
					Value: mockReleaseUrlLatest,
				},
			},
			want: &client.Repo{
				Owner: "mock",
				Repo:  "repo",
			},
			want1:   Latest,
			wantErr: false,
		},
		{
			name: "parse valid tag github url",
			args: args{
				source: datasource.Source{
					Value: mockReleaseUrlWithTag,
				},
			},
			want: &client.Repo{
				Owner: "mock",
				Repo:  "repo",
			},
			want1:   "v1",
			wantErr: false,
		},
		{
			name: "non-https github url",
			args: args{
				source: datasource.Source{
					Value: "http://github.com/mock/repo/releases",
				},
			},
			want:       nil,
			want1:      "",
			wantErr:    true,
			errMessage: errors.New("invalid github url scheme"),
		},
		{
			name: "non-github url",
			args: args{
				source: datasource.Source{
					Value: "https://githubs.com/mock/repo/releases",
				},
			},
			want:       nil,
			want1:      "",
			wantErr:    true,
			errMessage: errors.New("invalid github host: githubs.com"),
		},
		{
			name: "github url too short",
			args: args{
				source: datasource.Source{
					Value: "https://github.com/mock",
				},
			},
			want:       nil,
			want1:      "",
			wantErr:    true,
			errMessage: errors.New("invalid github url path: /mock invalid number of subpaths: 1"),
		},
		{
			name: "github url too long",
			args: args{
				source: datasource.Source{
					Value: "https://github.com/mock/repo/releases/v1/too/long",
				},
			},
			want:       nil,
			want1:      "",
			wantErr:    true,
			errMessage: errors.New("invalid github url path: /mock/repo/releases/v1/too/long invalid number of subpaths: 6"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := ParseGithubReleaseDataSource(tt.args.source)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("ParseGithubReleaseDataSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.errMessage.Error()) {
					t.Errorf("ParseGithubReleaseDataSource() error = %v, wantErr %v", err, tt.errMessage)
					return
				}
			} else {
				if tt.wantErr {
					t.Errorf("ParseGithubReleaseDataSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseGithubReleaseDataSource() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("ParseGithubReleaseDataSource() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

// URL should be in the form:
// <vcs_tool>+<transport>://<host_name>[/<path_to_repository>][@<revision_tag_or_branch>][#<sub_path>]
func Test_parseGitDataSource(t *testing.T) {
	type args struct {
		source datasource.Source
	}
	tests := []struct {
		name       string
		args       args
		want       *client.Repo
		want1      TagOrLatest
		wantErr    bool
		errMessage error
	}{
		{
			name: "parse valid latest git uri",
			args: args{
				source: datasource.Source{
					Value: "git+https://github.com/mock/repo",
				},
			},
			want: &client.Repo{
				Owner: "mock",
				Repo:  "repo",
			},
			want1:   Latest,
			wantErr: false,
		},
		{
			name: "parse valid tag git uri",
			args: args{
				source: datasource.Source{
					Value: "git+https://github.com/mock/repo@v1",
				},
			},
			want: &client.Repo{
				Owner: "mock",
				Repo:  "repo",
			},
			want1:   "v1",
			wantErr: false,
		},
		{
			name: "non-github uri",
			args: args{
				source: datasource.Source{
					Value: "git+https://githubs.com/mock/repo",
				},
			},
			want:       nil,
			want1:      "",
			wantErr:    true,
			errMessage: errors.New("invalid github host: githubs.com"),
		},
		{
			name: "git uri too short",
			args: args{
				source: datasource.Source{
					Value: "git+ssh://github.com/mock",
				},
			},
			want:       nil,
			want1:      "",
			wantErr:    true,
			errMessage: errors.New("invalid github uri path: /mock invalid number of subpaths: 1"),
		},
		{
			name: "git uri too long",
			args: args{
				source: datasource.Source{
					Value: "git+https://github.com/mock/repo/releases/v1/too/long",
				},
			},
			want:       nil,
			want1:      "",
			wantErr:    true,
			errMessage: errors.New("invalid github uri path: /mock/repo/releases/v1/too/long invalid number of subpaths: 6"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := ParseGitDataSource(tt.args.source)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("ParseGitDataSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.errMessage.Error()) {
					t.Errorf("ParseGitDataSource() error = %v, wantErr %v", err, tt.errMessage)
					return
				}
			} else {
				if tt.wantErr {
					t.Errorf("ParseGitDataSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseGitDataSource() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("ParseGitDataSource() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
