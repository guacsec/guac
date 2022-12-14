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
	"golang.org/x/oauth2"
)

const (
	CollectorGitHubDocument = "GitHubCollector"
)

type githubDocumentCollector struct {
	url           string
	dir           string
	lastChecked   time.Time
	poll          bool
	interval      time.Duration
	fileCollector collector.Collector
}

func NewGitHubDocumentCollector(ctx context.Context, url string, dir string, poll bool, interval time.Duration) *githubDocumentCollector {
	fileCollector := file.NewFileCollector(ctx, dir, false, time.Second)

	return &githubDocumentCollector{
		url:           url,
		dir:           dir,
		poll:          poll,
		interval:      interval,
		fileCollector: fileCollector,
	}
}

func (g *githubDocumentCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	// Replace with your own personal access token, export to use
	token := os.Getenv("API_KEY")

	// Replace with the owner and name of the repository
	owner := "slsa-framework"
	repo := "slsa-github-generator"

	// Replace with the path of the directory where you want to download the assets
	dir := "temp"

	// Create the directory if it doesn't exist
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Change the current working directory to the directory
	err = os.Chdir(dir)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Authenticate with GitHub
	ctx = context.Background()
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

	// Download each SBOM (.jsonl) asset in the release
	for _, asset := range release.Assets {
		// Check if the asset's name ends with .jsonl
		if !strings.HasSuffix(asset.GetName(), ".jsonl") {
			continue
		}

		// Get the asset's URL
		assetURL, err := url.Parse(asset.GetBrowserDownloadURL())
		if err != nil {
			fmt.Println(err)
			continue
		}

		// Create the file
		filename := asset.GetName()
		file, err := os.Create(filename)
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer file.Close()

		// Download the asset
		resp, err := http.Get(assetURL.String())
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer resp.Body.Close()

		// Write the asset to the file
		_, err = io.Copy(file, resp.Body)
		if err != nil {
			fmt.Println(err)
			continue
		}
	}
	return nil
}

func checkIfDirExists(name string) (bool, error) {
	_, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Type returns the collector type
func (g *githubDocumentCollector) Type() string {
	return CollectorGitHubDocument
}
