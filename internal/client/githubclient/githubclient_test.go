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

//go:build integrationMerge

package githubclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/guacsec/guac/internal/client"
	"github.com/guacsec/guac/internal/testing/testdata"
)

// Since these are integration tests, we are just going to call an environment variable.
// This environment variable should also be available to github actions which this project
// currently uses.
func getGithubTokenFromEnv() (string, error) {
	e := os.Getenv("GITHUB_TOKEN")
	if e == "" {
		return "", fmt.Errorf("GITHUB_TOKEN empty or unset")
	}
	return e, nil
}

func testGithubClient() *githubClient {
	ctx := context.Background()
	t, err := getGithubTokenFromEnv()
	if err != nil {
		panic(err)
	}

	g, err := NewGithubClient(ctx, t)
	if err != nil {
		panic(err)
	}

	return g
}

func TestNewGithubClient(t *testing.T) {
	token, err := getGithubTokenFromEnv()
	if err != nil {
		t.Fatalf("Unable to fetch token from environment, halting tests: %v", err)
	}
	type args struct {
		token string
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		errMessage error
	}{
		{
			name: "valid token for github client",
			args: args{
				token: token,
			},
			wantErr: false,
		},
		{
			name: "invalid token for github client",
			args: args{
				token: "fake token",
			},
			wantErr:    true,
			errMessage: errors.New("GET https://api.github.com/users: 401 Bad credentials []"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := NewGithubClient(ctx, tt.args.token)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("NewGithubClient() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.errMessage.Error()) {
					t.Errorf("NewGithubClient() error = %v, wantErr %v", err, tt.errMessage)
					return
				}
			} else {
				if tt.wantErr {
					t.Errorf("NewGithubClient() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
		})
	}
}

func Test_githubClient_GetLatestRelease(t *testing.T) {
	gc := testGithubClient()
	type args struct {
		ctx   context.Context
		owner string
		repo  string
	}
	tests := []struct {
		name       string
		args       args
		want       *client.Release
		wantErr    bool
		errMessage error
	}{
		{
			name: "fetch valid latest release",
			args: args{
				ctx:   context.Background(),
				owner: "guacsec",
				repo:  "guac-test",
			},
			want: &client.Release{
				Tag:    "v1",
				Commit: "a05760afde49e6f2bf24a40eae3079f515df9815",
				Assets: []client.ReleaseAsset{{
					Name: "small-spdx.json",
					URL:  "https://github.com/guacsec/guac-test/releases/download/v1/small-spdx.json",
				}},
			},
			wantErr: false,
		},
		{
			name: "fetch repo with no release",
			args: args{
				ctx:   context.Background(),
				owner: "guacsec",
				// TODO(mlieberman85): Change guac-data to another guac-test repo just in case we do releases
				// of example guac-data
				repo: "guac-data",
			},
			want:       nil,
			wantErr:    true,
			errMessage: errors.New("GET https://api.github.com/repos/guacsec/guac-data/releases/latest: 404 Not Found []"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gc.GetLatestRelease(tt.args.ctx, tt.args.owner, tt.args.repo)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("githubClient.GetLatestRelease() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.errMessage.Error()) {
					t.Errorf("githubClient.GetLatestRelease() error = %v, wantErr %v", err, tt.errMessage)
					return
				}
			} else {
				if tt.wantErr {
					t.Errorf("githubClient.GetLatestRelease() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("githubClient.GetLatestRelease() = %v, want %v", got, tt.want)
			}

		})
	}
}

func Test_githubClient_GetCommitSHA1(t *testing.T) {
	gc := testGithubClient()

	type args struct {
		ctx   context.Context
		owner string
		repo  string
		ref   string
	}
	tests := []struct {
		name       string
		args       args
		want       string
		wantErr    bool
		errMessage error
	}{
		{
			name: "get with valid ref",
			args: args{
				ctx:   context.Background(),
				owner: "guacsec",
				repo:  "guac-test",
				ref:   "v1",
			},
			want:    "a05760afde49e6f2bf24a40eae3079f515df9815",
			wantErr: false,
		},
		{
			name: "get with invalid ref",
			args: args{
				ctx:   context.Background(),
				owner: "guacsec",
				repo:  "guac-test",
				ref:   "doesnotexist",
			},
			want:       "",
			wantErr:    true,
			errMessage: errors.New("GET https://api.github.com/repos/guacsec/guac-test/commits/doesnotexist: 422 No commit found for SHA: doesnotexist []"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gc.GetCommitSHA1(tt.args.ctx, tt.args.owner, tt.args.repo, tt.args.ref)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("githubClient.GetCommitSHA1() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.errMessage.Error()) {
					t.Errorf("githubClient.GetCommitSHA1() error = %v, wantErr %v", err, tt.errMessage)
					return
				}
			} else {
				if tt.wantErr {
					t.Errorf("githubClient.GetCommitSHA1() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if got != tt.want {
				t.Errorf("githubClient.GetCommitSHA1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_githubClient_GetReleaseByTag(t *testing.T) {
	gc := testGithubClient()

	type args struct {
		ctx   context.Context
		owner string
		repo  string
		tag   string
	}
	tests := []struct {
		name       string
		args       args
		want       *client.Release
		wantErr    bool
		errMessage error
	}{
		{
			name: "get release with real tag",
			args: args{
				ctx:   context.Background(),
				owner: "guacsec",
				repo:  "guac-test",
				tag:   "v1",
			},
			want: &client.Release{
				Tag:    "v1",
				Commit: "a05760afde49e6f2bf24a40eae3079f515df9815",
				Assets: []client.ReleaseAsset{{
					Name: "small-spdx.json",
					URL:  "https://github.com/guacsec/guac-test/releases/download/v1/small-spdx.json",
				}},
			},
			wantErr: false,
		},
		{
			name: "get release with nonexistant tag",
			args: args{
				ctx:   context.Background(),
				owner: "guacsec",
				repo:  "guac-test",
				tag:   "nonexistant",
			},
			want:       nil,
			wantErr:    true,
			errMessage: errors.New("https://api.github.com/repos/guacsec/guac-test/releases/tags/nonexistant: 404 Not Found []"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gc.GetReleaseByTag(tt.args.ctx, tt.args.owner, tt.args.repo, tt.args.tag)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("githubClient.GetReleaseByTag() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.errMessage.Error()) {
					t.Errorf("githubClient.GetReleaseByTag() error = %v, wantErr %v", err, tt.errMessage)
					return
				}
			} else {
				if tt.wantErr {
					t.Errorf("githubClient.GetReleaseByTag() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("githubClient.GetReleaseByTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_githubClient_GetReleaseAsset(t *testing.T) {
	gc := testGithubClient()
	type args struct {
		asset client.ReleaseAsset
	}
	tests := []struct {
		name       string
		args       args
		want       *client.ReleaseAssetContent
		wantErr    bool
		errMessage error
	}{
		{
			name: "get real asset",
			args: args{
				asset: client.ReleaseAsset{
					Name: "small-spdx.json",
					URL:  "https://github.com/guacsec/guac-test/releases/download/v1/small-spdx.json",
				},
			},
			want: &client.ReleaseAssetContent{
				Name:  "small-spdx.json",
				Bytes: testdata.SpdxExampleSmall,
			},
			wantErr:    false,
			errMessage: nil,
		},
		{
			name: "get fake asset",
			args: args{
				asset: client.ReleaseAsset{
					Name: "fake-asset.json",
					URL:  "https://github.com/guacsec/guac-test/releases/download/v1/fake-asset.json",
				},
			},
			want:       nil,
			wantErr:    true,
			errMessage: errors.New("unable to fetch asset https://github.com/guacsec/guac-test/releases/download/v1/fake-asset.json, status: 404 Not Found"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gc.GetReleaseAsset(tt.args.asset)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("githubClient.GetReleaseAsset() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.errMessage.Error()) {
					t.Errorf("githubClient.GetReleaseAsset() error = %v, wantErr %v", err, tt.errMessage)
					return
				}
			} else {
				if tt.wantErr {
					t.Errorf("githubClient.GetReleaseAsset() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("githubClient.GetReleaseAsset() = %v, want %v", got, tt.want)
			}
		})
	}
}
