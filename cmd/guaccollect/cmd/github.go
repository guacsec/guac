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
	"os"
	"time"

	"github.com/guacsec/guac/internal/client/githubclient"
	csubclient "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/csubsource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/github"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type githubOptions struct {
	// datasource for the collector
	dataSource datasource.CollectSource
	// address for pubsub connection
	pubsubAddr string
	// address for blob store
	blobAddr string
	// run as poll collector
	poll bool
}

var githubCmd = &cobra.Command{
	Use:   "github [flags] release_url1 release_url2...",
	Short: "takes github repos and tags to download metadata documents stored in Github releases to add to GUAC graph utilizing Nats pubsub and blob store",
	Long: `
guaccollect github checks repos and tags to download metadata documents stored in Github releases. Ingestion to GUAC happens via an event stream (NATS)
to allow for decoupling of the collectors from the ingestion into GUAC. 

Each collector collects the "document" and stores it in the blob store for further
evaluation. The collector creates a CDEvent (https://cdevents.dev/) that is published via 
the event stream. The downstream guacingest subscribes to the stream and retrieves the "document" from the blob store for 
processing and ingestion.

Various blob stores can be used (such as S3, Azure Blob, Google Cloud Bucket) as documented here: https://gocloud.dev/howto/blob/
For example: "s3://my-bucket?region=us-west-1"

Specific authentication method vary per cloud provider. Please follow the documentation per implementation to ensure
you have access to read and write to the respective blob store.`,
	Args: cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateGithubFlags(
			viper.GetString("pubsub-addr"),
			viper.GetString("blob-addr"),
			viper.GetString("csub-addr"),
			viper.GetString("github-mode"),
			viper.GetString("github-sbom-name"),
			viper.GetString("github-workflow-file-name"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("use-csub"),
			viper.GetBool("service-poll"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

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
		}
		if opts.poll {
			collectorOpts = append(collectorOpts, github.WithPolling(30*time.Second))
		}
		githubCollector, err := github.NewGithubCollector(collectorOpts...)
		if err != nil {
			logger.Errorf("unable to create Github collector: %v", err)
		}
		err = collector.RegisterDocumentCollector(githubCollector, github.GithubCollector)
		if err != nil {
			logger.Errorf("unable to register Github collector: %v", err)
		}

		initializeNATsandCollector(ctx, opts.pubsubAddr, opts.blobAddr)
	},
}

func validateGithubFlags(pubsubAddr, blobAddr, csubAddr, githubMode, sbomName, workflowFileName string, csubTls, csubTlsSkipVerify, useCsub, poll bool, args []string) (githubOptions, error) {
	var opts githubOptions
	opts.pubsubAddr = pubsubAddr
	opts.blobAddr = blobAddr
	opts.poll = poll

	if useCsub {
		csubOpts, err := csubclient.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
		if err != nil {
			return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
		}
		c, err := csubclient.NewClient(csubOpts)
		if err != nil {
			return opts, err
		}
		opts.dataSource, err = csubsource.NewCsubDatasource(c, 10*time.Second)
		return opts, err
	}

	// else direct CLI call
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

	return opts, nil
}

func init() {
	rootCmd.AddCommand(githubCmd)
}
