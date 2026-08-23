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
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"github.com/google/go-github/v50/github"
	"github.com/guacsec/guac/internal/client"
	"github.com/guacsec/guac/pkg/version"
	"golang.org/x/oauth2"
	"io"
	"net/http"
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

	// GetWorkflow fetches the workflow for a given workflow name or all workflows if the workflow name is empty
	GetWorkflow(ctx context.Context, owner string, repo string, githubWorkflowName string) ([]*client.Workflow, error)

	// GetLatestWorkflowRun fetches all the workflow run for a given workflow id
	GetLatestWorkflowRun(ctx context.Context, owner, repo string, workflowId int64) (*client.WorkflowRun, error)

	// GetWorkflowRunArtifacts fetches all the workflow run artifacts for a given workflow run id
	GetWorkflowRunArtifacts(ctx context.Context, owner, repo, githubSBOMName string, runID int64) ([]*client.WorkflowArtifactContent, error)
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

// GetWorkflow retrieves the workflow for a specified workflow name from a given GitHub repository.
// If the workflow name is not provided, it fetches all workflows for the repository.
// It returns an error if the workflow name is provided but not found in the repository.
func (gc *githubClient) GetWorkflow(ctx context.Context, owner, repo, githubWorkflowFileName string) ([]*client.Workflow, error) {
	if githubWorkflowFileName != "" {
		workflow, _, err := gc.ghClient.Actions.GetWorkflowByFileName(ctx, owner, repo, githubWorkflowFileName)
		if err != nil {
			return nil, fmt.Errorf("unable to get workflow by file name: %w", err)
		}

		return []*client.Workflow{
			{
				Name: *workflow.Name,
				Id:   *workflow.ID,
			},
		}, nil
	}

	workflows, _, err := gc.ghClient.Actions.ListWorkflows(ctx, owner, repo, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to list workflows: %w", err)
	}

	var res []*client.Workflow

	for _, workflow := range workflows.Workflows {
		res = append(res, &client.Workflow{
			Name: *workflow.Name,
			Id:   *workflow.ID,
		})
	}

	return res, nil
}

// GetLatestWorkflowRun retrieves all the workflow runs associated with a specified workflow ID from a given GitHub repository.
// It returns an error if the workflow runs cannot be fetched.
func (gc *githubClient) GetLatestWorkflowRun(ctx context.Context, owner, repo string, workflowId int64) (*client.WorkflowRun, error) {
	runs, _, err := gc.ghClient.Actions.ListWorkflowRunsByID(ctx, owner, repo, workflowId, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to list workflow runs: %w", err)
	}

	if len(runs.WorkflowRuns) == 0 {
		return nil, nil
	}

	// runs.WorkflowRuns is sorted by created_at in descending order so the first element is the latest run
	return &client.WorkflowRun{WorkflowId: *runs.WorkflowRuns[0].WorkflowID, RunId: *runs.WorkflowRuns[0].ID}, nil
}

func (gc *githubClient) GetWorkflowRunArtifacts(ctx context.Context, owner, repo, githubSBOMName string, runID int64) ([]*client.WorkflowArtifactContent, error) {
	var res []*client.WorkflowArtifactContent

	// get workflow run artifacts
	artifacts, _, err := gc.ghClient.Actions.ListWorkflowRunArtifacts(ctx, owner, repo, runID, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to list workflow run artifacts: %w", err)
	}
	for _, j := range artifacts.Artifacts {
		// If the githubSBOMName is empty, we want to return all artifacts
		// Otherwise, we only want to return the artifacts that have the name of githubSBOMName
		if githubSBOMName != "" && *j.Name != githubSBOMName {
			continue
		}

		// download artifact
		file, _, err := gc.ghClient.Actions.DownloadArtifact(ctx, owner, repo, j.GetID(), true)
		if err != nil {
			return nil, fmt.Errorf("unable to download artifact: %w", err)
		}

		arr, err := DownloadAndExtractZip(file.String(), runID)
		if err != nil {
			return nil, fmt.Errorf("unable to download and extract zip: %w", err)
		}

		res = append(res, arr...)
	}

	return res, nil
}

// DownloadAndExtractZip downloads a zip file from the given URL, extracts its contents,
// and returns only those files that are valid JSON.
func DownloadAndExtractZip(url string, runID int64) ([]*client.WorkflowArtifactContent, error) {
	// Download the zip file
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error getting zip file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	// Read the body into a buffer
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Read the zip archive
	zipReader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		return nil, fmt.Errorf("error reading zip file: %w", err)
	}

	var files []*client.WorkflowArtifactContent

	// Iterate through each file in the archive
	for _, zipFile := range zipReader.File {
		f, err := zipFile.Open()
		if err != nil {
			return nil, fmt.Errorf("error opening file in zip: %w", err)
		}
		defer f.Close()

		fileData := make([]byte, zipFile.UncompressedSize64)
		_, err = io.ReadFull(f, fileData)
		if err != nil {
			return nil, fmt.Errorf("error reading file data: %w", err)
		}

		files = append(files, &client.WorkflowArtifactContent{Name: zipFile.Name, Bytes: fileData, RunId: runID})
	}

	return files, nil
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
