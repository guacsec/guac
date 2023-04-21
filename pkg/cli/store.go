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

package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/pflag"
)

var flagStore = make(map[string]*pflag.Flag)

var NotFound = errors.New("Flag not found")

func init() {
	set := &pflag.FlagSet{}

	// Set of all flags used across GUAC clis and subcommands. Use consistant
	// names for config file.
	set.String("natsaddr", "nats://127.0.0.1:4222", "address to connect to NATs Server")
	set.String("csub-addr", "localhost:2782", "address to connect to collect-sub service")
	set.Bool("use-csub", true, "use collectsub server for datasource")

	set.Int("csub-listen-port", 2782, "port to listen to on collect-sub service")

	set.String("gql-backend", "inmem", "backend used for graphql api server: [neo4j | inmem]")
	set.Int("gql-port", 8080, "port used for graphql api server")
	set.Bool("gql-debug", false, "debug flag which enables the graphQL playground")
	set.Bool("gql-testdata", false, "Populate backend with test data")

	set.String("gdbaddr", "neo4j://localhost:7687", "address to neo4j db")
	set.String("gdbuser", "", "neo4j user credential to connect to graph db")
	set.String("gdbpass", "", "neo4j password credential to connect to graph db")
	set.String("realm", "neo4j", "realm to connect to graph db")

	set.String("gql-endpoint", "http://localhost:8080/query", "endpoint used to connect to graphQL server")

	set.String("verifier-keyPath", "", "path to pem file to verify dsse")
	set.String("verifier-keyID", "", "ID of the key to be stored")

	set.BoolP("poll", "p", true, "sets the collector or certifier to polling mode")
	set.IntP("interval", "i", 5, "if polling set interval in minutes")

	set.BoolP("good", "g", true, "set true if certifyGood or false for certifyBad")
	set.StringP("type", "t", "", "package, source or artifact that is being certified")
	set.StringP("justification", "j", "", "justification for the certification (either good or bad)")
	set.BoolP("pkgName", "n", false, "if type is package, true if attestation is at pkgName (for all versions) or false for a specific version")

	set.String("purl", "", "package purl to check")
	set.String("vulnerabilityID", "", "CVE, GHSA or OSV ID to check")
	set.Int("depth", 0, "depth to check, 0 has no limit")
	set.Int("path", 0, "number of paths to return, 0 means all paths")

	set.VisitAll(func(f *pflag.Flag) {
		flagStore[f.Name] = f
	})
}

func BuildFlags(names []string) (*pflag.FlagSet, error) {
	rv := &pflag.FlagSet{}
	for _, n := range names {
		f, ok := flagStore[n]
		if !ok {
			return nil, fmt.Errorf("%w : %s", NotFound, n)
		}
		rv.AddFlag(f)
	}
	return rv, nil
}
