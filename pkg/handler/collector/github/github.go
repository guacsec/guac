package github

import (
	"context"
	"errors"
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
	poll     bool
	interval time.Duration
	token    string
	owner    string
	repo     string
	tag      string
	tagList  []string
}

func NewGitHubDocumentCollector(ctx context.Context, poll bool, interval time.Duration, logger *zap.SugaredLogger, token string, owner string, repo string, tag string, tagList []string) *githubDocumentCollector {
	return &githubDocumentCollector{
		poll:     poll,
		interval: interval,
		token:    token,
		owner:    owner,
		repo:     repo,
		tag:      tag,
		tagList:  []string{},
	}
}

// RetrieveArtifacts collects the metadata documents and assets from a specified Github repository's release
func (g *githubDocumentCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
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
	if !contains(g.tagList, currentTag) {
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

			doc := &processor.Document{
				Blob:   bytes,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(CollectorGitHubDocument),
					Source:    currentTag,
				},
			}
			docChannel <- doc
		}

		g.tagList = append(g.tagList, currentTag)
	}

	return nil
}

func contains(elems []string, v string) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}
