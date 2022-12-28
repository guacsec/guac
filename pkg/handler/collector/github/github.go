package github

import (
	"context"
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
	CollectorGitHubDocument = "GitHubCollector"
)

type githubDocumentCollector struct {
	dir      string
	poll     bool
	interval time.Duration
	token    string
	owner    string
	repo     string
	tag      string
	tagList  []string
}

func NewGitHubDocumentCollector(ctx context.Context, dir string, poll bool, interval time.Duration, logger *zap.SugaredLogger, token string, owner string, repo string, tag string, latestRelease bool) *githubDocumentCollector {
	return &githubDocumentCollector{
		dir:      dir,
		poll:     poll,
		interval: interval,
		token:    token,
		owner:    owner,
		repo:     repo,
		tag:      tag,
	}
}

func (g *githubDocumentCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	if g.poll {
		for {
			if ctx.Err() != nil {
				return nil
			}
			err := g.fetchAssets(ctx, logger, docChannel)
			if err != nil {
				return err
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
func (g *githubDocumentCollector) Type() string {
	return CollectorGitHubDocument
}

// Getting files from assets
func (g *githubDocumentCollector) fetchAssets(ctx context.Context, logger *zap.SugaredLogger, docChannel chan<- *processor.Document) error {
	// Authenticate with GitHub
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: g.token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// Get information about the release
	var release *github.RepositoryRelease
	var err error

	if g.tag == "" {
		// get the latest release
		release, _, err = client.Repositories.GetLatestRelease(ctx, g.owner, g.repo)
	} else {
		// get the release with the specified tag
		release, _, err = client.Repositories.GetReleaseByTag(ctx, g.owner, g.repo, g.tag)
	}
	if err != nil {
		logger.Debug(err)
		return err
	}
	// Add the current tag to the tagList if it has not been seen before
	currentTag := release.GetTagName()
	found := false
	for _, t := range g.tagList {
		if t == currentTag {
			found = true
			break
		}
	}
	if !found {
		// Download each asset in the release
		for _, asset := range release.Assets {
			// Check if the asset's name ends with .jsonl
			if !strings.HasSuffix(asset.GetName(), ".jsonl") {
				continue
			}

			// Get the asset's URL
			assetURL, err := url.Parse(asset.GetBrowserDownloadURL())
			if err != nil {
				logger.Error(err)
				continue
			}

			// Download the asset
			resp, err := http.Get(assetURL.String())
			if err != nil {
				logger.Error(err)
				continue
			}
			defer resp.Body.Close()

			bytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			var sourceString string

			if g.tag == "" {
				sourceString = fmt.Sprintf("repos/%s/%s/releases/latest", g.owner, g.repo)
			} else {
				sourceString = fmt.Sprintf("repos/%s/%s/releases/tags/%s", g.owner, g.repo, g.tag)
			}
			doc := &processor.Document{
				Blob:   bytes,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(CollectorGitHubDocument),
					Source:    sourceString,
				},
			}
			docChannel <- doc
		}

		g.tagList = append(g.tagList, currentTag)
	}

	return nil
}
