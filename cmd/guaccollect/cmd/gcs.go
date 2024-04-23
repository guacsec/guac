package cmd

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/storage"
	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/gcs"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/api/option"
)

type gcsOptions struct {
	pubSubAddr        string
	blobAddr          string
	graphqlEndpoint   string
	csubClientOptions csub_client.CsubClientOptions
	bucket            string
}

const gcsCredentialsPathFlag = "gcp-credentials-path"

var gcsCmd = &cobra.Command{
	Use:     "gcs [flags] bucket_name",
	Short:   "takes SBOMs and attestations from a Google Cloud Storage bucket and injects them to GUAC graph. This command talks directly to the graphQL endpoint",
	Example: "guacone collect gcs my-bucket --gcs-credentials-path /secret/sa.json",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateGCSFlags(
			viper.GetString("pubsub-addr"),
			viper.GetString("blob-addr"),
			viper.GetString("gql-addr"),
			viper.GetString("csub-addr"),
			viper.GetString(gcsCredentialsPathFlag),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		gcsOpts := []option.ClientOption{
			option.WithUserAgent(version.UserAgent),
		}

		// Credential flag is not mandatory since they can also be loaded from
		// the environment variable GOOGLE_APPLICATION_CREDENTIALS by the client, by default
		if credsPath := viper.GetString(gcsCredentialsPathFlag); credsPath != "" {
			gcsOpts = append(gcsOpts, option.WithCredentialsFile(credsPath))
		}

		client, err := storage.NewClient(ctx, gcsOpts...)
		if err != nil {
			logger.Fatalf("creating client: %v", err)
		}

		// Register collector
		gcsCollector, err := gcs.NewGCSCollector(gcs.WithBucket(opts.bucket), gcs.WithClient(client))
		if err != nil {
			logger.Fatalf("unable to create gcs client: %v", err)
		}

		err = collector.RegisterDocumentCollector(gcsCollector, gcs.CollectorGCS)
		if err != nil {
			logger.Fatalf("unable to register gcs collector: %v", err)
		}

		// initialize collectsub client
		csubClient, err := csub_client.NewClient(opts.csubClientOptions)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		initializeNATsandCollector(ctx, opts.pubSubAddr, opts.blobAddr)
	},
}

func validateGCSFlags(
	pubSubAddr,
	blobAddr,
	gqlEndpoint,
	csubAddr,
	credentialsPath string,
	csubTls,
	csubTlsSkipVerify bool,
	args []string,
) (gcsOptions, error) {
	opts := gcsOptions{
		pubSubAddr:      pubSubAddr,
		blobAddr:        blobAddr,
		graphqlEndpoint: gqlEndpoint,
	}

	csubOpts, err := csub_client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}
	opts.csubClientOptions = csubOpts

	if len(args) < 1 {
		return opts, fmt.Errorf("expected positional argument: bucket")
	}
	opts.bucket = args[0]

	if credentialsPath == "" && os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		return opts, fmt.Errorf("expected either --%s flag or GOOGLE_APPLICATION_CREDENTIALS environment variable", gcsCredentialsPathFlag)
	}

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{gcsCredentialsPathFlag})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	gcsCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(gcsCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(gcsCmd)
}
