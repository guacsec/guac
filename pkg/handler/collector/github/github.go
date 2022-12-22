package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/github"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	CollectorGitHubDocument = "GitHubCollector"
)

type githubDocumentCollector struct {
	dir           string
	lastChecked   time.Time
	poll          bool
	interval      time.Duration
	fileCollector collector.Collector
	token         string
	owner         string
	repo          string
}

func NewGitHubDocumentCollector(ctx context.Context, dir string, poll bool, interval time.Duration, logger *zap.SugaredLogger, token string, owner string, repo string) *githubDocumentCollector {
	fileCollector := file.NewFileCollector(ctx, dir, false, time.Second)

	return &githubDocumentCollector{
		dir:           dir,
		poll:          poll,
		interval:      interval,
		fileCollector: fileCollector,
		token:         token,
		owner:         owner,
		repo:          repo,
	}
}

func (g *githubDocumentCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	if g.poll {
		for {
			if ctx.Err() != nil {
				return nil
			}
			err := g.collectAssets(g.dir, g.owner, g.repo, g.token, logger, docChannel)
			if err != nil {
				return err
			}
			g.lastChecked = time.Now()
			time.Sleep(g.interval)
		}
	} else {
		err := g.collectAssets(g.dir, g.owner, g.repo, g.token, logger, docChannel)
		if err != nil {
			return err
		}
		g.lastChecked = time.Now()
	}

	return nil
}

// Type returns the collector type
func (g *githubDocumentCollector) Type() string {
	return CollectorGitHubDocument
}

// Getting files from assets
func (g *githubDocumentCollector) collectAssets(directory string, owner string, repo string, token string, logger *zap.SugaredLogger, docChannel chan<- *processor.Document) error {
	// API_KEY needs to be stored as an environmental variable: export API_KEY="YOUR_KEY_HERE"

	// Create the directory if it doesn't exist
	err := os.MkdirAll(directory, 0755)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Change the current working directory to the directory
	err = os.Chdir(directory)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Authenticate with GitHub
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// Get information about the latest release
	release, _, err := client.Repositories.GetLatestRelease(ctx, owner, repo)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Download each asset in the release
	for _, asset := range release.Assets {
		// Check if the asset's name ends with .jsonl
		if !strings.HasSuffix(asset.GetName(), ".jsonl") {
			continue
		}

		// NOTE: Asset download stpe 1
		// Get the asset's URL
		assetURL, err := url.Parse(asset.GetBrowserDownloadURL())
		if err != nil {
			fmt.Println(err)
			continue
		}

		// NOTE: Asset download step 2
		// Create the file
		filename := asset.GetName()
		file, err := os.Create(filename)
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer file.Close()

		// NOTE: Asset download step 3
		// Download the asset
		resp, err := http.Get(assetURL.String())
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer resp.Body.Close()

		// NOTE: Asset download step 4
		// Write the asset to the file
		_, err = io.Copy(file, resp.Body)
		if err != nil {
			fmt.Println(err)
			continue
		}

		err = g.fileCollector.RetrieveArtifacts(ctx, docChannel)
		if err != nil {
			return err
		}
	}

	return nil
}
