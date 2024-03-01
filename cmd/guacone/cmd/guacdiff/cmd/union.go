package cmd

import (
	// "context"
	// "net/http"

	// "github.com/Khan/genqlient/graphql"
	// "github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	// "github.com/spf13/viper"
)

var unionCmd = &cobra.Command{
	Use:   "union",
	Short: "Get a union of two given SBOMS",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		// slsas, errSlsa := cmd.Flags().GetStringSlice("slsa")
		// sboms, errSbom := cmd.Flags().GetStringSlice("sboms")
		// uri, _ := cmd.Flags().GetBool("uri")
		// purl, _ := cmd.Flags().GetBool("purl")

		// metadata, _ := cmd.Flags().GetBool("metadata")
		// inclSoft, _ := cmd.Flags().GetBool("inclSoft")
		// inclDeps, _ := cmd.Flags().GetBool("inclDeps")
		// inclOccur, _ := cmd.Flags().GetBool("inclOccur")
		// namespaces, _ := cmd.Flags().GetBool("namespaces")
		// list, _ := cmd.Flags().GetBool("list")
		// ctx := logging.WithLogger(context.Background())
		// httpClient := http.Client{}
		// gqlclient := graphql.NewClient(viper.GetString("gql-addr"), &httpClient)


	},
}



func init() {
	rootCmd.AddCommand()
	// rootCmd.PersistentFlags().StringSlice("sboms", []string{}, "two sboms to find the diff between")
	// rootCmd.PersistentFlags().StringSlice("slsa", []string{}, "two slsa to find the diff between")
	// rootCmd.PersistentFlags().Bool("uri", false, "input is a URI")
	// rootCmd.PersistentFlags().Bool("purl", false, "input is a pURL")
	// rootCmd.PersistentFlags().Bool("metadata", false, "Union of SBOM metadata")
	// rootCmd.PersistentFlags().Bool("inclSoft", false, "Union of Included Softwares")
	// rootCmd.PersistentFlags().Bool("inclDeps", false, "Union of Included Dependencies")
	// rootCmd.PersistentFlags().Bool("inclOccur", false, "Union of Included Occurrences")
	// rootCmd.PersistentFlags().Bool("namespaces", false, "Union of Package Namespaces")
	
}
