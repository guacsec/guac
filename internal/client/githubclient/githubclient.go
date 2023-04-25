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

package githubclient

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-github/v50/github"
	"github.com/guacsec/guac/internal/client"
	"github.com/guacsec/guac/pkg/version"
	"golang.org/x/oauth2"
)

// TODO (mlieberman85): This interface will probably be pulled out into an interface that can support other
// services with artifact releases like Gitlab
// Wrapper interface for Github
type GithubClient interface {
	// GetLatestRelease fetches the latest release for a repo
	GetLatestRelease(ctx context.Context, owner string, repo string) (*client.Release, error)

	// GetCommitSHA1 fetches the commit SHA in a repo based on a tag, branch head, or other ref.
	// NOTE: Github release 2022-11-28 and similar server returns a commitish for a release.
	// The release commitish can be a commit, branch name, or a tag.
	// We need to resolve it to a commit.
	GetCommitSHA1(ctx context.Context, owner string, repo string, ref string) (string, error)

	// GetReleaseByTagSlices fetches metadata regarding releases for a given tag. If the tag is the empty string,
	// it should just return the latest.
	GetReleaseByTag(ctx context.Context, owner string, repo string, tag string) (*client.Release, error)

	// GetReleaseAsset fetches the content of a release asset, e.g. artifacts, metadata documents, etc.
	GetReleaseAsset(asset client.ReleaseAsset) (*client.ReleaseAssetContent, error)
}

type githubClient struct {
	ghClient   *github.Client
	httpClient *http.Client
}

var _ GithubClient = &githubClient{}

func NewGithubClient(ctx context.Context, token string) (*githubClient, error) {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := &http.Client{
		Transport: &oauth2.Transport{
			Source: ts,
			Base:   version.UATransport,
		},
	}
	gc := github.NewClient(tc)

	// Run a simple API call to verify authentication to Github API.
	// If it fails we can error out quickly
	_, r, err := gc.Users.ListAll(ctx, nil)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("expected status code 200 for github client, got: %v", r.StatusCode)
	}

	return &githubClient{
		ghClient:   gc,
		httpClient: http.DefaultClient,
	}, nil
}

func (gc *githubClient) GetLatestRelease(ctx context.Context, owner string, repo string) (*client.Release, error) {
	githubRelease, _, err := gc.ghClient.Repositories.GetLatestRelease(ctx, owner, repo)
	if err != nil {
		return nil, err
	}

	currentTag := githubRelease.GetTagName()

	sha, err := gc.GetCommitSHA1(ctx, owner, repo, currentTag)
	if err != nil {
		return nil, err
	}

	var assets []client.ReleaseAsset
	for _, asset := range githubRelease.Assets {
		assets = append(assets, client.ReleaseAsset{
			Name: *asset.Name,
			URL:  *asset.BrowserDownloadURL,
		})
	}

	release := client.Release{
		Tag:    *githubRelease.TagName,
		Commit: sha,
		Assets: assets,
	}

	return &release, nil
}

func (gc *githubClient) GetCommitSHA1(ctx context.Context, owner string, repo string, ref string) (string, error) {
	commit, _, err := gc.ghClient.Repositories.GetCommitSHA1(ctx, owner, repo, ref, "")

	return commit, err
}

func (gc *githubClient) GetReleaseByTag(ctx context.Context, owner string, repo string, tag string) (*client.Release, error) {
	githubRelease, _, err := gc.ghClient.Repositories.GetReleaseByTag(ctx, owner, repo, tag)
	if err != nil {
		return nil, err
	}

	sha, err := gc.GetCommitSHA1(ctx, owner, repo, tag)
	if err != nil {
		return nil, err
	}

	var assets []client.ReleaseAsset
	for _, asset := range githubRelease.Assets {
		assets = append(assets, client.ReleaseAsset{
			Name: *asset.Name,
			URL:  *asset.BrowserDownloadURL,
		})
	}

	release := client.Release{
		Tag:    *githubRelease.TagName,
		Commit: sha,
		Assets: assets,
	}

	return &release, nil
}

func (gc *githubClient) GetReleaseAsset(asset client.ReleaseAsset) (*client.ReleaseAssetContent, error) {
	resp, err := gc.httpClient.Get(asset.URL)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unable to fetch asset %v, status: %v", asset.URL, resp.Status)
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &client.ReleaseAssetContent{
		Name:  asset.Name,
		Bytes: bytes,
	}, nil
}
