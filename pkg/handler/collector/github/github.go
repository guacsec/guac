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
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/guacsec/guac/internal/client"
	"github.com/guacsec/guac/internal/client/githubclient"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	GithubCollector = "GithubCollector"
	Latest          = ""
)

func defaultAssetSuffixes() []string {
	return []string{".jsonl"}
}

// TagOrLatest is either a tag or if it's the empty string "" then it should be considered latest
type TagOrLatest = string

type githubCollector struct {
	poll              bool
	interval          time.Duration
	client            githubclient.GithubClient
	repoToReleaseTags map[client.Repo][]TagOrLatest
	assetSuffixes     []string
	collectDataSource datasource.CollectSource
	isRelease         bool
	sbomName          string
	workflowFileName  string
	owner             string
	repo              string
	lastIngestedRun   int64
}

type Config struct {
	Poll              bool
	Interval          time.Duration
	Client            githubclient.GithubClient
	RepoToReleaseTags map[client.Repo][]TagOrLatest
	AssetSuffixes     []string
	CollectDataSource datasource.CollectSource
}

type Opt func(*githubCollector)

func NewGithubCollector(opts ...Opt) (*githubCollector, error) {
	g := &githubCollector{
		poll:              false,
		interval:          0,
		client:            nil,
		repoToReleaseTags: map[client.Repo][]TagOrLatest{},
		assetSuffixes:     defaultAssetSuffixes(),
		collectDataSource: nil,
	}

	for _, opt := range opts {
		opt(g)
	}

	if g.client == nil {
		return nil, fmt.Errorf("no github client provided for collector")
	}
	if len(g.assetSuffixes) == 0 {
		return nil, fmt.Errorf("no asset suffixes for github collector")
	}
	if len(g.repoToReleaseTags) == 0 && g.collectDataSource == nil {
		return nil, fmt.Errorf("no repos and releases to collect nor any data source for future subscriptions")
	}
	return g, nil
}

func WithPolling(interval time.Duration) Opt {
	return func(g *githubCollector) {
		g.poll = true
		g.interval = interval
	}
}

func WithRelease(githubMode string) Opt {
	return func(g *githubCollector) {
		if githubMode == "release" || githubMode == "" {
			g.isRelease = true
		} else {
			g.isRelease = false // otherwise it is a workflow
		}
	}
}

func WithSbomName(sbomName string) Opt {
	return func(g *githubCollector) {
		g.sbomName = sbomName
	}
}

func WithWorkflowName(workflowName string) Opt {
	return func(g *githubCollector) {
		g.workflowFileName = workflowName
	}
}

func WithOwner(owner string) Opt {
	return func(g *githubCollector) {
		g.owner = owner
	}
}

func WithRepo(repo string) Opt {
	return func(g *githubCollector) {
		g.repo = repo
	}
}

func WithClient(client githubclient.GithubClient) Opt {
	return func(g *githubCollector) {
		g.client = client
	}
}

func WithRepoToReleaseTags(repoToReleaseTags map[client.Repo][]TagOrLatest) Opt {
	return func(g *githubCollector) {
		g.repoToReleaseTags = repoToReleaseTags
	}
}

func WithAssetSuffixes(assetSuffixes []string) Opt {
	return func(g *githubCollector) {
		g.assetSuffixes = assetSuffixes
	}
}

func WithCollectDataSource(collectDataSource datasource.CollectSource) Opt {
	return func(g *githubCollector) {
		g.collectDataSource = collectDataSource
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (g *githubCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if g.isRelease {
		err := g.populateRepoToReleaseTags(ctx)
		if err != nil {
			return err
		}
		if g.poll {
			for repo, tags := range g.repoToReleaseTags {
				g.fetchAssets(ctx, repo.Owner, repo.Repo, tags, docChannel)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(g.interval):
			}
		} else {
			for repo, tags := range g.repoToReleaseTags {
				g.fetchAssets(ctx, repo.Owner, repo.Repo, tags, docChannel)
			}
		}
	} else {
		if g.poll {
			g.fetchWorkflowRunArtifacts(ctx, g.owner, g.repo, docChannel)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(g.interval):
			}
		} else {
			g.fetchWorkflowRunArtifacts(ctx, g.owner, g.repo, docChannel)
		}
	}

	return nil
}

func (g *githubCollector) Type() string {
	return GithubCollector
}

func (g *githubCollector) populateRepoToReleaseTags(ctx context.Context) error {
	logger := logging.FromContext(ctx)
	if g.collectDataSource == nil {
		return nil
	}
	ds, err := g.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	for _, grds := range ds.GithubReleaseDataSources {
		r, t, err := ParseGithubReleaseDataSource(grds)
		if err != nil {
			logger.Warnf("unable to parse github datasource: %v", err)
			continue
		}
		g.repoToReleaseTags[*r] = append(g.repoToReleaseTags[*r], t)
	}

	for _, gds := range ds.GitDataSources {
		r, t, err := ParseGitDataSource(gds)
		if err != nil {
			logger.Warnf("unable to parse git datasource: %v", err)
			continue
		}
		g.repoToReleaseTags[*r] = append(g.repoToReleaseTags[*r], t)
	}

	return nil
}

func (g *githubCollector) fetchAssets(ctx context.Context, owner string, repo string, tags []TagOrLatest, docChannel chan<- *processor.Document) {
	logger := logging.FromContext(ctx)
	var releases []client.Release
	for _, gitTag := range tags {
		var release *client.Release
		var err error
		switch gitTag {
		case "":
			release, err = g.client.GetLatestRelease(ctx, owner, repo)
		default:
			release, err = g.client.GetReleaseByTag(ctx, owner, repo, gitTag)
		}
		if err != nil {
			logger.Warnf("unable to fetch release: %v", err)
			continue
		}
		releases = append(releases, *release)
	}

	for _, release := range releases {
		g.collectAssetsForRelease(ctx, release, docChannel)
	}
}

func (g *githubCollector) collectAssetsForRelease(ctx context.Context, release client.Release, docChannel chan<- *processor.Document) {
	logger := logging.FromContext(ctx)
	for _, asset := range release.Assets {
		if ctx.Err() != nil {
			return
		}
		if checkSuffixes(asset.URL, g.assetSuffixes) {
			content, err := g.client.GetReleaseAsset(asset)
			if err != nil {
				logger.Warnf("unable to download asset: %v", err)
				continue
			}
			doc := &processor.Document{
				Blob:   content.Bytes,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: GithubCollector,
					Source:    asset.URL,
				},
			}
			docChannel <- doc
		}
	}
}

// fetchWorkflowRunArtifacts fetches the artifacts from the GitHub Action Workflow runs for a given owner and repo.
// The artifacts are then sent to the provided docChannel.
// If an error occurs while fetching a workflow run or its artifacts, it is logged and the function continues to the next workflow run.
func (g *githubCollector) fetchWorkflowRunArtifacts(ctx context.Context, owner string, repo string, docChannel chan<- *processor.Document) {
	logger := logging.FromContext(ctx)

	workflows, err := g.client.GetWorkflow(ctx, owner, repo, g.workflowFileName)
	if err != nil {
		logger.Warnf("unable to fetch workflows: %v", err)
		return
	}

	for _, workflow := range workflows {
		// get the latest workflow run
		run, err := g.client.GetWorkflowRuns(ctx, owner, repo, workflow.Id)
		if err != nil {
			logger.Warnf("unable to fetch workflow runs for workflow %v: %v", workflow.Id, err)
			continue
		}
		if run == nil {
			logger.Warnf("no workflow runs found for workflow %v", workflow.Id)
			continue
		}

		// don't re-ingest the same run
		if run.RunId == g.lastIngestedRun {
			continue
		}

		fmt.Println("run.RunId: ", run.RunId)

		artifacts, err := g.client.GetWorkflowRunArtifacts(ctx, owner, repo, g.sbomName, g.workflowFileName)
		if err != nil {
			logger.Warnf("unable to fetch workflow run artifacts for run %v: %v", run.RunId, err)
			continue
		}

		for _, artifact := range artifacts {
			doc := &processor.Document{
				Blob:   artifact.Bytes,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: GithubCollector,
					Source:    artifact.Name,
				},
			}
			docChannel <- doc
		}

		g.lastIngestedRun = run.RunId
	}
}

func checkSuffixes(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	return false
}

// TODO (mlieberman85): Parse* below are helpers both used by the collector as well as others
// to parse data sources into internal structs used by various components.
// This should be moved into another location for helpers.

// ParseGithubReleaseDataSource takes in a data source and parses it assuming it's a Github URL
func ParseGithubReleaseDataSource(source datasource.Source) (*client.Repo, TagOrLatest, error) {
	u, err := url.Parse(source.Value)
	if err != nil {
		return nil, "", err
	}
	if u.Scheme != "https" {
		return nil, "", fmt.Errorf("invalid github url scheme: %v", u.Scheme)
	}
	if u.Host != "github.com" {
		return nil, "", fmt.Errorf("invalid github host: %v", u.Host)
	}

	// The below split path should look something like:
	// [ "orgName" "repoName" "releases" ]
	// [ "orgName" "repoName" "releases" "tag"]
	// [1:] to ignore leading slash
	path := strings.Split(u.Path, "/")[1:]
	if len(path) < 3 || len(path) > 5 {
		return nil, "", fmt.Errorf("invalid github url path: %v invalid number of subpaths: %v", u.Path, len(path))
	}
	if path[2] != "releases" || (len(path) == 5 && path[3] != "tags") {
		return nil, "", fmt.Errorf("invalid github path: %v", u.Path)
	}
	var tol TagOrLatest
	if len(path) == 5 {
		tol = path[4]
	} else if len(path) == 4 {
		tol = path[3]
	} else {
		tol = Latest
	}
	r := &client.Repo{
		Owner: path[0],
		Repo:  path[1],
	}

	return r, tol, nil
}

// ParseGitDataSource takes in a data
// URL should be in the form:
// <vcs_tool>+<transport>://<host_name>[/<path_to_repository>][@<revision_tag_or_branch>][#<sub_path>]
func ParseGitDataSource(source datasource.Source) (*client.Repo, TagOrLatest, error) {
	//using vcs.go helper functions
	var tol TagOrLatest
	var r *client.Repo
	/*
		Lines 294-301 are repetitive, this check can be done in VcsToSrc function
	*/
	u, err := url.Parse(source.Value)
	if err != nil {
		return nil, "", err
	}
	if u.Host != "github.com" {
		return nil, "", fmt.Errorf("invalid github host: %v", u.Host)
	}

	path := strings.Split(u.Path, "/")[1:]
	if len(path) != 2 {
		return nil, "", fmt.Errorf("invalid github uri path: %v invalid number of subpaths: %v", u.Path, len(path))
	}
	m, err := helpers.VcsToSrc(source.Value)
	if err != nil {
		return nil, "", err
	}

	if m.Tag == nil && m.Commit == nil {
		tol = Latest
	} else if m.Tag != nil {
		tol = *m.Tag
	} else if m.Commit != nil {
		tol = *m.Commit
	}
	r = &client.Repo{
		Owner: m.GetNamespace()[strings.Index(m.GetNamespace(), "/")+1:],
		Repo:  m.GetName(),
	}
	return r, tol, nil
}
