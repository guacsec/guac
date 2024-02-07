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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// lookupCmd represents the lookup command
var lookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Query GraphQL for any packages that exist with a given specification",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		id, _ := cmd.Flags().GetString("id")
		uri, _ := cmd.Flags().GetString("uri")
		purl, _ := cmd.Flags().GetString("purl")
		algorithm, _ := cmd.Flags().GetString("algorithm")
		digest, _ := cmd.Flags().GetString("digest")
		downloadLocation, _ := cmd.Flags().GetString("download-location")
		origin, _ := cmd.Flags().GetString("origin")
		collector, _ := cmd.Flags().GetString("collector")

		all, _ := cmd.Flags().GetBool("all")
		max, _ := cmd.Flags().GetInt("max")
		if max < 1 {
			fmt.Printf("Max must be greater than 0\n")
			os.Exit(1)
		}
		wide, _ := cmd.Flags().GetBool("wide")

		ctx := logging.WithLogger(context.Background())
		httpClient := http.Client{}
		gqlclient := graphql.NewClient(viper.GetString("gql-addr"), &httpClient)

		hasSBOMResponse, err := findHasSBOMBy(id, uri, purl, algorithm, digest, downloadLocation, origin, collector, ctx, gqlclient)
		if err != nil {
			return
		}
		allSBOMResponses := hasSBOMResponse.HasSBOM
		if len(allSBOMResponses) == 0 {
			fmt.Printf("No Package could be found with given specification\n")
			return
		}

		if wide {
			showWideOutput(allSBOMResponses)
		} else {
			printNarrowOutput(allSBOMResponses, all, max)
		}

	},
}

func printNarrowOutput(allSBOMResponses []model.HasSBOMsHasSBOM, all bool, max int) {

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	fmt.Fprintln(w, "ID\tURI\tAlgorithm\tDigest\tDownload Location\tOrigin\tCollector\tKnown Since")

	for i, obj := range allSBOMResponses {
		// Truncate all values
		id := truncate(obj.Id, 10)
		uri := truncate(obj.Uri, 25)
		algorithm := truncate(obj.Algorithm, 10)
		digest := truncate(obj.Digest, 10)
		downloadLocation := truncate(obj.DownloadLocation, 25)
		origin := truncate(obj.Origin, 15)
		collector := truncate(obj.Collector, 15)
		knownSince := truncate(obj.KnownSince.Format(time.RFC3339), 15)

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n\n",
			id, uri, algorithm, digest, downloadLocation, origin, collector, knownSince)

		fmt.Fprintln(w, strings.Repeat("-", 80))
		if !all && len(allSBOMResponses) > max && i == max-1 {
			break
		}
	}
	w.Flush()
	if !all && len(allSBOMResponses) > max {
		fmt.Print("Run with --all to list all packages that match the specification or specify max with a preferred number\n")
	}
}
func showWideOutput(allSBOMResponses []model.HasSBOMsHasSBOM) {

	tmpfile, err := os.CreateTemp("", "example*.json")
	if err != nil {
		fmt.Errorf("Error creating temporary file:", err)
		return
	}
	defer os.Remove(tmpfile.Name())

	jsonData, err := json.MarshalIndent(allSBOMResponses, "", "  ")
	if err != nil {
		fmt.Errorf("Error marshalling JSON: %v", err)
		return
	}

	if _, err := tmpfile.Write([]byte(jsonData)); err != nil {
		fmt.Errorf("Error writing to temporary file:", err)
		return
	}

	if err := tmpfile.Close(); err != nil {
		fmt.Errorf("Error closing temporary file:", err)
		return
	}

	cmd := exec.Command("more", tmpfile.Name())

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Errorf("Error executing less: %v", err)
		return
	}

	if err := cmd.Wait(); err != nil {
		fmt.Errorf("Error waiting for less to finish: %v", err)
		return
	}
}

// func print
func findHasSBOMBy(id, uri, purl, algorithm, digest, downloadLocation, origin, collector string, ctx context.Context, gqlclient graphql.Client) (*model.HasSBOMsResponse, error) {
	var foundHasSBOMPkg *model.HasSBOMsResponse
	var err error
	if purl != "" {
		pkgResponse, err := getPkgResponseFromPurl(ctx, gqlclient, purl)
		if err != nil {
			fmt.Printf("getPkgResponseFromPurl - error: %v", err)
			return nil, err
		}
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{Package: &model.PkgSpec{Id: &pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id}},
			Id: &id, Digest: &digest, DownloadLocation: &downloadLocation, Origin: &origin, Collector: &collector})
		if err != nil {
			fmt.Printf("failed getting hasSBOM with error :%v", err)
			return nil, err
		}
	} else {
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Uri: &uri, Id: &id, Digest: &digest, DownloadLocation: &downloadLocation, Origin: &origin, Collector: &collector})
		if err != nil {
			fmt.Printf("failed getting hasSBOM  with error: %v", err)
			return nil, err
		}
	}
	return foundHasSBOMPkg, nil
}

func init() {
	rootCmd.AddCommand(lookupCmd)
	//these flags are used to lookup SBOMs that meet the flag criteria, all mentioned flags are ANDed together
	lookupCmd.PersistentFlags().String("id", "", "id for SBOM to lookup")
	lookupCmd.PersistentFlags().String("uri", "", "uri for SBOM to lookup")
	lookupCmd.PersistentFlags().String("purl", "", "pURL for SBOM to lookup")
	lookupCmd.PersistentFlags().String("algorithm", "", "algorithm for SBOM  to lookup")
	lookupCmd.PersistentFlags().String("digest", "", "digest for SBOM to lookup")
	lookupCmd.PersistentFlags().String("download-location", "", "download-location SBOM to lookup")
	lookupCmd.PersistentFlags().String("origin", "", "origin for SBOM to lookup")
	lookupCmd.PersistentFlags().String("collector", "", "collector for SBOM to lookup")
	lookupCmd.PersistentFlags().Bool("all", false, "Print the first few SBOMs found, if any")
	lookupCmd.PersistentFlags().Bool("wide", false, "Print with all occurrences, packages, and dependencies for found SBOMs")
	lookupCmd.PersistentFlags().Int("max", 5, "Print only max number of SBOMs found (Min 1), if any")
}
