//
// Copyright 2022 The GUAC Authors.
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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-github/github"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	CollectorGitHub = "GitHubCollector"
)

type githubCollector struct {
	poll     bool
	interval time.Duration
	token    string
	client   *github.Client
	owner    string
	repo     string
	tag      string
	tagMap   map[string]string
}

type GithubCollectorOpts struct {
	poll     bool
	interval time.Duration
	token    string
	owner    string
	repo     string
	tag      string
}

func NewGitHubCollector(ctx context.Context, gco GithubCollectorOpts) (*githubCollector, error) {
	err := validateOpts(gco)
	if err != nil {
		return nil, err
	}
	// Authenticate with GitHub
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: gco.token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	return &githubCollector{
		poll:     gco.poll,
		interval: gco.interval,
		token:    gco.token,
		client:   client,
		owner:    gco.owner,
		repo:     gco.repo,
		tag:      gco.tag,
		tagMap:   map[string]string{},
	}, nil
}

func validateOpts(gco GithubCollectorOpts) error {
	if gco.owner == "" {
		return fmt.Errorf("expected to receive GitHub owner")
	}
	if gco.repo == "" {
		return fmt.Errorf("expected to receive GitHub repo")
	}
	if gco.token == "" {
		return fmt.Errorf("expected to receive GitHub token")
	}
	return nil
}

// RetrieveArtifacts collects the metadata documents and assets from a specified Github repository's release
func (g *githubCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	if g.poll {
		for {
			if ctx.Err() != nil {
				return nil
			}
			// Check if no poll is passed in, should only poll for latest releases
			if g.tag != "" {
				return errors.New("release tag should not specified when using polling")
			}
			if g.tag == "" {
				err := g.fetchAssets(ctx, logger, docChannel)
				if err != nil {
					return err
				}
			}
			time.Sleep(g.interval)
		}
	} else {
		err := g.fetchAssets(ctx, logger, docChannel)
		if err != nil {
			return err
		}
	}

	return nil
}

// Type returns the collector type
func (g *githubCollector) Type() string {
	return CollectorGitHub
}

// Getting files from assets
func (g *githubCollector) fetchAssets(ctx context.Context, logger *zap.SugaredLogger, docChannel chan<- *processor.Document) error {

	// Get information about the release
	var release *github.RepositoryRelease
	var err error

	if g.tag == "" {
		// get the latest release
		release, _, err = g.client.Repositories.GetLatestRelease(ctx, g.owner, g.repo)
	} else {
		// get the release with the specified tag
		release, _, err = g.client.Repositories.GetReleaseByTag(ctx, g.owner, g.repo, g.tag)
	}
	if err != nil {
		new_error := fmt.Errorf("unable to fetch assets...%w", err)
		logger.Debug(new_error)
		return new_error
	}
	// Add the current tag to the tagMap if it has not been seen before
	currentTag := release.GetTagName()
	currentHash, _, err := g.client.Repositories.GetCommitSHA1(ctx, g.owner, g.repo, currentTag, "")
	if err != nil {
		new_error := fmt.Errorf("unable to fetch commit for tag...%w", err)
		logger.Error(new_error)
		return new_error
	}
	if g.tagMap[currentTag] != currentHash {
		// Download each asset in the release
		for _, asset := range release.Assets {
			// Check if the asset's name ends with .jsonl
			if !strings.HasSuffix(asset.GetName(), ".jsonl") {
				continue
			}

			// Get the asset's URL
			assetURL, err := url.Parse(asset.GetBrowserDownloadURL())
			if err != nil {
				new_err := fmt.Errorf("unable to get asset URLs... %w", err)
				logger.Error(new_err)
				continue
			}

			// Download the asset
			resp, err := http.Get(assetURL.String())
			if err != nil {
				new_err := fmt.Errorf("unable to download asset URLs... %w", err)
				logger.Error(new_err)
				continue
			}
			defer resp.Body.Close()

			bytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			doc := &processor.Document{
				Blob:   bytes,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(CollectorGitHub),
					Source:    currentTag,
				},
			}
			docChannel <- doc
		}

		g.tagMap[currentTag] = currentHash
	}

	return nil
}
