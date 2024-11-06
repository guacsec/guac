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

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/collectsub/datasource/csubsource"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"

	"os/signal"

	"github.com/guacsec/guac/internal/client/githubclient"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/github"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	githubMode         = "github-mode"
	githubSbom         = "github-sbom"
	githubWorkflowFile = "github-workflow-file"
)

type githubOptions struct {
	// datasource for the collector
	dataSource datasource.CollectSource
	// run as poll collector
	poll bool
	// the mode to run the collector in
	githubMode string
	// the name of the sbom file to look for
	sbomName string
	// the name of the workflow file to look for
	workflowFileName string
	// the owner/repo name to use for the collector
	ownerRepoName string
	// csub client options for identifier strings
	csubClientOptions csub_client.CsubClientOptions
	// graphql endpoint
	graphqlEndpoint         string
	headerFile              string
	queryVulnOnIngestion    bool
	queryLicenseOnIngestion bool
	queryEOLOnIngestion     bool
	queryDepsDevOnIngestion bool
}

var githubCmd = &cobra.Command{
	Use:   "github if <github-mode> is \"release\" then [flags] release_url1 release_url2..., otherwise if <github-mode> is \"workflow\" then [flags] <owner>/<repo>",
	Short: "takes github repos and tags to download metadata documents stored in Github releases to add to GUAC graph.",
	Long: `Takes github repos and tags to download metadata documents stored in Github releases to add to GUAC graph.
  if <github-mode> is "release" then [flags] release_url1 release_url2..., otherwise if <github-mode> is "workflow" then [flags] <owner>/<repo>.`,
	Args: cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateGithubFlags(
			viper.GetString("gql-addr"),
			viper.GetString("header-file"),
			viper.GetString(githubMode),
			viper.GetString(githubSbom),
			viper.GetString(githubWorkflowFile),
			viper.GetString("csub-addr"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("use-csub"),
			viper.GetBool("poll"),
			viper.GetBool("add-vuln-on-ingest"),
			viper.GetBool("add-license-on-ingest"),
			viper.GetBool("add-eol-on-ingest"),
			viper.GetBool("add-depsdev-on-ingest"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

		// GITHUB_TOKEN is the default token name
		ghc, err := githubclient.NewGithubClient(ctx, os.Getenv("GITHUB_TOKEN"))
		if err != nil {
			logger.Errorf("unable to create github client: %v", err)
		}

		// Register collector
		// TODO(lumjjb and mlieberman85): Return this to a longer duration (~10 minutes) so as
		// to not keep hitting Github. This will require adding triggers to get new repos as
		// they come up from the CollectSources so that there isn't a long delay from
		// adding new data sources.
		collectorOpts := []github.Opt{
			github.WithCollectDataSource(opts.dataSource),
			github.WithClient(ghc),
			github.WithMode(opts.githubMode),
			github.WithSbomName(opts.sbomName),
			github.WithWorkflowName(opts.workflowFileName),
		}
		if opts.poll {
			collectorOpts = append(collectorOpts, github.WithPolling(30*time.Second))
		}
		if opts.ownerRepoName != "" {
			if !strings.Contains(opts.ownerRepoName, "/") {
				logger.Errorf("owner-repo flag must be in the format <owner>/<repo>")
			} else {
				ownerRepoName := strings.Split(opts.ownerRepoName, "/")
				if len(ownerRepoName) != 2 {
					logger.Errorf("owner-repo flag must be in the format <owner>/<repo>")
				}
				collectorOpts = append(collectorOpts, github.WithOwner(ownerRepoName[0]))
				collectorOpts = append(collectorOpts, github.WithRepo(ownerRepoName[1]))
			}
		}
		githubCollector, err := github.NewGithubCollector(collectorOpts...)
		if err != nil {
			logger.Errorf("unable to create Github collector: %v", err)
		}
		err = collector.RegisterDocumentCollector(githubCollector, github.GithubCollector)
		if err != nil {
			logger.Errorf("unable to register Github collector: %v", err)
		}

		csubClient, err := csub_client.NewClient(opts.csubClientOptions)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		var errFound bool

		emit := func(d *processor.Document) error {
			_, err := ingestor.Ingest(
				ctx,
				d,
				opts.graphqlEndpoint,
				transport,
				csubClient,
				opts.queryVulnOnIngestion,
				opts.queryLicenseOnIngestion,
				opts.queryEOLOnIngestion,
				opts.queryDepsDevOnIngestion,
			)
			if err != nil {
				errFound = true
				return fmt.Errorf("unable to ingest document: %w", err)
			}
			return nil
		}

		errHandler := func(err error) bool {
			if err == nil {
				logger.Info("collector ended gracefully")
				return true
			}
			logger.Errorf("collector ended with error: %v", err)
			return false
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		// Use a wait group to wait for the collector to finish
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := collector.Collect(ctx, emit, errHandler); err != nil {
				logger.Fatal(err)
			}
		}()

		select {
		case <-sigs:
			logger.Info("Signal received, shutting down gracefully")
			cancel()
		case <-ctx.Done():
			logger.Info("Collector finished")
		}

		wg.Wait()
		logger.Info("Shutdown complete")

		if errFound {
			logger.Fatalf("completed ingestion with error")
		} else {
			logger.Infof("completed ingestion")
		}
	},
}

func validateGithubFlags(graphqlEndpoint, headerFile, githubMode, sbomName, workflowFileName, csubAddr string, csubTls,
	csubTlsSkipVerify, useCsub, poll bool, queryVulnIngestion bool, queryLicenseIngestion bool, queryEOLIngestion bool, queryDepsDevOnIngestion bool, args []string) (githubOptions, error) {
	var opts githubOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.headerFile = headerFile
	opts.poll = poll
	opts.githubMode = githubMode
	opts.sbomName = sbomName
	opts.workflowFileName = workflowFileName
	opts.queryVulnOnIngestion = queryVulnIngestion
	opts.queryLicenseOnIngestion = queryLicenseIngestion
	opts.queryEOLOnIngestion = queryEOLIngestion
	opts.queryDepsDevOnIngestion = queryDepsDevOnIngestion

	if useCsub {
		csubOpts, err := csub_client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
		if err != nil {
			return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
		}
		c, err := csub_client.NewClient(csubOpts)
		if err != nil {
			return opts, err
		}
		opts.dataSource, err = csubsource.NewCsubDatasource(c, 10*time.Second)
		return opts, err
	}

	// Otherwise direct CLI call

	if githubMode == "release" {
		if len(args) < 1 {
			return opts, fmt.Errorf("expected positional argument(s) for release_url(s)")
		}

		sources := []datasource.Source{}
		for _, arg := range args {
			// TODO (mlieberman85): Below should be a github url parser helper instead of in the github collector
			if _, _, err := github.ParseGithubReleaseDataSource(datasource.Source{
				Value: arg,
			}); err != nil {
				return opts, fmt.Errorf("release_url parsing error. require format https://github.com/<org>/<repo>/releases/<optional_tag>: %v", err)
			}
			sources = append(sources, datasource.Source{
				Value: arg,
			})
		}

		var err error
		opts.dataSource, err = inmemsource.NewInmemDataSources(&datasource.DataSources{
			GithubReleaseDataSources: sources,
		})
		if err != nil {
			return opts, err
		}
	} else {
		if len(args) != 1 {
			return opts, fmt.Errorf("expected positional argument for owner-repo in the format <owner>/<repo>")
		}
		opts.ownerRepoName = args[0]
		if opts.ownerRepoName == "" {
			return opts, fmt.Errorf("owner-repo argument must be in the format <owner>/<repo>")
		}
	}

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{githubMode, githubSbom, githubWorkflowFile, "use-csub", "poll"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	githubCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(githubCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	collectCmd.AddCommand(githubCmd)
}
