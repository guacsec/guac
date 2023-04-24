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
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type certifyOptions struct {
	// gql endpoint
	graphqlEndpoint string
	// // certifyBad/certifyGood
	good          bool
	certifyType   string
	justification string
	subject       string
	// // if type is package, true if attestation is at pkgName (for all versions) or false for a specific version
	pkgName bool
}

var certifyCmd = &cobra.Command{
	Use:              "certify [flags] purl / source (<vcs_tool>+<transport>) / artifact (algorithm:digest)",
	Short:            "certify can either certify a package, source or artifact to be good or bad based on a justification",
	TraverseChildren: true,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateCertifyFlags(
			viper.GetString("gql-endpoint"),
			viper.GetString("type"),
			viper.GetString("justification"),
			viper.GetBool("good"),
			viper.GetBool("pkgName"),
			args,
		)

		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		assemblerFunc, err := getAssembler(ctx, opts.graphqlEndpoint)
		if err != nil {
			logger.Fatalf("error: %v", err)
		}

		preds := &assembler.IngestPredicates{}
		var pkgInput *model.PkgInputSpec
		var matchFlag model.MatchFlags
		var srcInput *model.SourceInputSpec
		var artifact *model.ArtifactInputSpec

		if opts.certifyType == "package" {
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
		} else if opts.certifyType == "source" {
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

		if opts.good {
			certifyGood := &assembler.CertifyGoodIngest{}
			if pkgInput != nil {
				certifyGood.Pkg = pkgInput
				certifyGood.Pkg = pkgInput
				certifyGood.PkgMatchFlag = matchFlag

			} else if srcInput != nil {
				certifyGood.Src = srcInput
			} else {
				certifyGood.Artifact = artifact
			}
			certifyGood.CertifyGood = &model.CertifyGoodInputSpec{
				Justification: opts.justification,
				Origin:        "GUAC Certify CLI",
				Collector:     "GUAC",
			}
			preds.CertifyGood = append(preds.CertifyGood, *certifyGood)
		} else {
			certifyBad := &assembler.CertifyBadIngest{}
			if pkgInput != nil {
				certifyBad.Pkg = pkgInput
				certifyBad.Pkg = pkgInput
				certifyBad.PkgMatchFlag = matchFlag

			} else if srcInput != nil {
				certifyBad.Src = srcInput
			} else {
				certifyBad.Artifact = artifact
			}
			certifyBad.CertifyBad = &model.CertifyBadInputSpec{
				Justification: opts.justification,
				Origin:        "GUAC Certify CLI",
				Collector:     "GUAC",
			}
			preds.CertifyBad = append(preds.CertifyBad, *certifyBad)
		}

		assemblerInputs := []assembler.IngestPredicates{*preds}

		err = assemblerFunc(assemblerInputs)
		if err != nil {
			logger.Fatalf("unable to assemble graphs: %v", err)
		}
	},
}

func validateCertifyFlags(graphqlEndpoint, certifyType, justification string, good, pkgName bool, args []string) (certifyOptions, error) {
	var opts certifyOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.good = good
	opts.pkgName = pkgName
	if certifyType != "package" && certifyType != "source" && certifyType != "artifact" {
		return opts, fmt.Errorf("expected type to be either a package, source or artifact")
	}
	opts.certifyType = certifyType
	if justification == "" {
		return opts, fmt.Errorf("missing justification")
	}
	opts.justification = justification
	if len(args) != 1 {
		return opts, fmt.Errorf("expected positional argument for subject")
	}

	opts.subject = args[0]

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"good", "type", "justification", "pkgName"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	certifyCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(certifyCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(certifyCmd)
}
