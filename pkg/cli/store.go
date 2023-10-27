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

const (
	ConfigLogLevelVar = "log-level"
)

var NotFound = errors.New("Flag not found")

func init() {
	set := &pflag.FlagSet{}

	// Set of all flags used across GUAC clis and subcommands. Use consistent
	// names for config file.
	set.String("nats-addr", "nats://127.0.0.1:4222", "address to connect to NATs Server")
	set.String("csub-addr", "localhost:2782", "address to connect to collect-sub service")
	set.Bool("csub-tls", false, "enable tls connection to the server")
	set.Bool("csub-tls-skip-verify", false, "skip verifying server certificate (for self-signed certificates for example)")
	set.Bool("use-csub", true, "use collectsub server for datasource")

	set.Int("csub-listen-port", 2782, "port to listen to on collect-sub service")
	set.String("csub-tls-cert-file", "", "path to the TLS certificate in PEM format for collect-sub service")
	set.String("csub-tls-key-file", "", "path to the TLS key in PEM format for collect-sub service")

	set.String("gql-backend", "inmem", "backend used for graphql api server: [inmem | arango (experimental) | ent (experimental) | neo4j (unmaintained)]")
	set.Int("gql-listen-port", 8080, "port used for graphql api server")
	set.String("gql-tls-cert-file", "", "path to the TLS certificate in PEM format for graphql api server")
	set.String("gql-tls-key-file", "", "path to the TLS key in PEM format for graphql api server")
	set.Bool("gql-debug", false, "debug flag which enables the graphQL playground")
	set.Bool("gql-trace", false, "flag which enables tracing of graphQL requests and responses on the console")

	set.String("neo4j-addr", "neo4j://localhost:7687", "address to neo4j db")
	set.String("neo4j-user", "", "neo4j user credential to connect to graph db")
	set.String("neo4j-pass", "", "neo4j password credential to connect to graph db")
	set.String("neo4j-realm", "neo4j", "realm to connect to graph db")

	set.String("neptune-endpoint", "localhost", "address to neptune db")
	set.Int("neptune-port", 8182, "port used for neptune db connection")
	set.String("neptune-region", "us-east-1", "region to connect to neptune db")
	set.String("neptune-user", "", "neptune user credential to connect to graph db")
	set.String("neptune-realm", "neptune", "realm to connect to graph db")

	set.String("db-address", "postgres://localhost/guac_dev", "Full URL of database to connect to")
	set.String("db-driver", "postgres", "database driver to use, one of [postgres | sqlite3 | mysql] or anything supported by sql.DB")
	set.Bool("db-debug", false, "enable debug logging for database queries")
	set.Bool("db-migrate", true, "automatically run database migrations on start")

	set.String("arango-addr", "http://localhost:8529", "address to arango db")
	set.String("arango-user", "", "arango user to connect to graph db")
	set.String("arango-pass", "", "arango password to connect to graph db")

	set.String("gql-addr", "http://localhost:8080/query", "endpoint used to connect to graphQL server")

	set.String("verifier-key-path", "", "path to pem file to verify dsse")
	set.String("verifier-key-id", "", "ID of the key to be stored")

	set.Bool("service-poll", true, "sets the collector or certifier to polling mode")
	set.BoolP("poll", "p", false, "sets the collector or certifier to polling mode")

	set.Bool("retrieve-dependencies", true, "enable the deps.dev collector to retrieve package dependencies")

	set.StringP("interval", "i", "5m", "if polling set interval, m, h, s, etc.")

	set.BoolP("cert-good", "g", false, "enable to certifyGood, otherwise defaults to certifyBad")
	set.BoolP("package-name", "n", false, "if type is package, enable if attestation is at package-name level (for all versions), defaults to specific version")

	set.IntP("search-depth", "d", 0, "depth to search, 0 has no limit")

	set.StringP("vuln-id", "v", "", "vulnerability ID to check")
	set.Int("num-path", 0, "number of paths to return, 0 means all paths")
	set.String("start-purl", "", "string input of purl with package to start search from")
	set.String("stop-purl", "", "string input of purl with package to stop search at")
	set.Bool("is-pkg-version-start", false, "for query path are you inputting a packageVersion to start the search from (if false then packageName)")
	set.Bool("is-pkg-version-stop", false, "for query path are you inputting a packageVersion to stop the search at (if false then packageName)")

	// Google Cloud platform flags
	set.String("gcp-credentials-path", "", "Path to the Google Cloud service account credentials json file.\nAlternatively you can set GOOGLE_APPLICATION_CREDENTIALS=<path> in your environment.")

	// S3 flags
	set.String("s3-url", "", "url of the s3 endpoint")
	set.String("s3-bucket", "", "bucket in the s3 provider")
	set.String("s3-item", "", "item in the s3 provider")
	set.String("s3-mp", "kafka", "message provider (sqs or kafka)")
	set.String("s3-mp-endpoint", "", "endpoint for the message provider")
	set.String("s3-queues", "", "comma-separated list of queue/topic names")
	set.String("s3-region", "us-east-1", "aws region")

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
