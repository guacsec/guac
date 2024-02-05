/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/guacsec/guac/pkg/version"
)



// 
var rootCmd = &cobra.Command{
	Use:   "guacident",
	Short: "",
	Long: ``,
	Version: version.Version,

}

//
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}


