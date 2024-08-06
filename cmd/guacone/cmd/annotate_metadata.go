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
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type annotateMetadataOptions struct {
	graphqlEndpoint string
	headerFile      string
	subjectType     string
	subject         string
	key             string
	value           string
	justification   string
	pkgName         bool
}

var annotateMetadata = &cobra.Command{
	Use:   "annotate-metadata [flags] <type> <subject> <key> <value>",
	Short: "Annotate metadata can add metadata to any package, source or artifact.",
	Long: `Annotate metadata can add metadata to any package, source or artifact.
  <type> must be either "package", "source", or "artifact".
  <subject> is in the form of "<purl>" for package, "<vcs_tool>+<transport>" for source, or "<algorithm>:<digest>" for artifact.
  <key> is a string representing key in the key value pair.
  <value> is a string representing value in key value pair.`,
	TraverseChildren: true,
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateMetadataFlags(
			viper.GetString("gql-addr"),
			viper.GetString("header-file"),
			viper.GetBool("package-name"),
			viper.GetString("justification"),
			args,
		)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

		assemblerFunc := ingestor.GetAssembler(ctx, logger, opts.graphqlEndpoint, transport)

		preds := &assembler.IngestPredicates{}
		var pkgInput *model.PkgInputSpec
		var matchFlag model.MatchFlags
		var srcInput *model.SourceInputSpec
		var artifact *model.ArtifactInputSpec

		if opts.subjectType == "package" {
			pkgInput, err = helpers.PurlToPkg(opts.subject)
			if err != nil {
				logger.Fatalf("failed to parse PURL: %v", err)
			}
			if opts.pkgName {
				matchFlag = model.MatchFlags{
					Pkg: model.PkgMatchTypeAllVersions,
				}
			} else {
				matchFlag = model.MatchFlags{
					Pkg: model.PkgMatchTypeSpecificVersion,
				}
			}
		} else if opts.subjectType == "source" {
			srcInput, err = helpers.VcsToSrc(opts.subject)
			if err != nil {
				logger.Fatalf("failed to parse source: %v", err)
			}
		} else {
			split := strings.Split(opts.subject, ":")
			if len(split) != 2 {
				logger.Fatalf("failed to parse artifact. Needs to be in algorithm:digest form")
			}
			artifact = &model.ArtifactInputSpec{
				Algorithm: strings.ToLower(string(split[0])),
				Digest:    strings.ToLower(string(split[1])),
			}
		}

		metadata := assembler.HasMetadataIngest{
			Pkg:          pkgInput,
			PkgMatchFlag: matchFlag,
			Src:          srcInput,
			Artifact:     artifact,
			HasMetadata: &model.HasMetadataInputSpec{
				Key:           opts.key,
				Value:         opts.value,
				Justification: opts.justification,
				Timestamp:     time.Now(),
			},
		}

		preds.HasMetadata = append(preds.HasMetadata, metadata)
		assemblerInputs := []assembler.IngestPredicates{*preds}

		_, err = assemblerFunc(assemblerInputs)
		if err != nil {
			logger.Fatalf("unable to assemble graphs: %v", err)
		}
	},
}

func validateMetadataFlags(graphqlEndpoint, headerFile string, pkgName bool, justification string, args []string) (annotateMetadataOptions, error) {
	var opts annotateMetadataOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.headerFile = headerFile
	opts.pkgName = pkgName
	opts.justification = justification
	if opts.justification == "" {
		opts.justification = "Added by user via guacone"
	}
	if len(args) != 4 {
		return opts, fmt.Errorf("expected positional arguments for <type> <subject> <key> <value>")
	}
	opts.subjectType = args[0]
	if opts.subjectType != "package" && opts.subjectType != "source" && opts.subjectType != "artifact" {
		return opts, fmt.Errorf("expected type to be either \"package\", \"source\", or \"artifact\"")
	}
	opts.subject = args[1]
	opts.key = args[2]
	opts.value = args[3]

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"package-name", "justification"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	annotateMetadata.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(annotateMetadata.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(annotateMetadata)
}
