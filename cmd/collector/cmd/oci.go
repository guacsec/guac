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

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/oci"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ociCmd = &cobra.Command{
	Use:   "image [flags] image_path1 image_path2...",
	Short: "takes images to download sbom and attestation stored in OCI to add to GUAC graph",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateOCIFlags(
			viper.GetString("natsaddr"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// Register collector
		ociCollector := oci.NewOCICollector(ctx, opts.repoTags, false, 10*time.Minute)
		err = collector.RegisterDocumentCollector(ociCollector, oci.OCICollector)
		if err != nil {
			logger.Errorf("unable to register oci collector: %v", err)
		}

		initializeNATsandCollector(ctx, opts.natsAddr)
	},
}

func validateOCIFlags(natsAddr string, args []string) (options, error) {
	var opts options

	opts.natsAddr = natsAddr
	opts.repoTags = map[string][]string{}

	if len(args) < 1 {
		return opts, fmt.Errorf("expected positional argument for image_path")
	}
	for _, arg := range args {
		stringSplit := strings.Split(arg, ":")
		if len(stringSplit) == 2 {
			opts.repoTags[stringSplit[0]] = append(opts.repoTags[stringSplit[0]], stringSplit[1])
		} else {
			return opts, fmt.Errorf("image_path parsing error. require format repo:tag")
		}
	}

	return opts, nil
}

func init() {
	rootCmd.AddCommand(ociCmd)
}
