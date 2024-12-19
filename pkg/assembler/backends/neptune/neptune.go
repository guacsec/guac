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

package neptune

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/neo4j"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const neptuneServiceName = "neptune-db"

type NeptuneConfig struct {
	Endpoint string
	Port     int
	Region   string
	User     string
	Realm    string
}

// flags holds the command-line flags for Neptune configuration
var flags = struct {
	endpoint string
	port     int
	region   string
	user     string
	realm    string
}{}

func init() {
	backends.Register("neptune", getBackend, registerFlags, parseFlags)
}

// registerFlags registers Neptune-specific command line flags
func registerFlags(cmd *cobra.Command) error {
	flagSet := cmd.Flags()
	flagSet.StringVar(&flags.endpoint, "neptune-endpoint", "localhost", "address to neptune db")
	flagSet.IntVar(&flags.port, "neptune-port", 8182, "port used for neptune db connection")
	flagSet.StringVar(&flags.region, "neptune-region", "us-east-1", "region to connect to neptune db")
	flagSet.StringVar(&flags.user, "neptune-user", "", "neptune user credential to connect to graph db")
	flagSet.StringVar(&flags.realm, "neptune-realm", "neptune", "realm to connect to graph db")

	if err := viper.BindPFlags(flagSet); err != nil {
		return fmt.Errorf("failed to bind flags: %w", err)
	}

	// set values from guac.yaml if present
	flags.endpoint = viper.GetString("neptune-endpoint")
	flags.port = viper.GetInt("neptune-port")
	flags.region = viper.GetString("neptune-region")
	flags.user = viper.GetString("neptune-user")
	flags.realm = viper.GetString("neptune-realm")

	return nil
}

// parseFlags returns the Neptune configuration from parsed flags
func parseFlags(ctx context.Context) (backends.BackendArgs, error) {
	return &NeptuneConfig{
		Endpoint: flags.endpoint,
		Port:     flags.port,
		Region:   flags.region,
		User:     flags.user,
		Realm:    flags.realm,
	}, nil
}

func getBackend(ctx context.Context, args backends.BackendArgs) (backends.Backend, error) {
	config, ok := args.(*NeptuneConfig)
	if !ok {
		return nil, fmt.Errorf("failed to assert neptune config from backend args")
	}
	neptuneRequestURL := fmt.Sprintf("https://%s:%d/opencypher",
		config.Endpoint, config.Port)
	neptuneToken, err := generateNeptuneToken(neptuneRequestURL,
		config.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create password for neptune: %w", err)
	}

	neptuneDBAddr := fmt.Sprintf("bolt+s://%s:%d/opencypher",
		config.Endpoint, config.Port)
	nargs := &neo4j.Neo4jConfig{
		User:   config.User,
		Pass:   neptuneToken,
		DBAddr: neptuneDBAddr,
		Realm:  config.Realm,
	}
	return backends.Get("neo4j", ctx, nargs)
}

// generateNeptuneToken generates a token for neptune using the AWS SDK.
func generateNeptuneToken(neptuneURL string, region string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, neptuneURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating http request for neptune: %w", err)
	}

	signer, err := getAWSRequestSigner()
	if err != nil {
		return "", fmt.Errorf("error creating AWS request signer: %w", err)
	}

	if _, err := signer.Sign(req, nil, neptuneServiceName, region, time.Now()); err != nil {
		return "", fmt.Errorf("error signing neptune request: %w", err)
	}

	headers := []string{"Authorization", "X-Amz-Date", "X-Amz-Security-Token"}
	hdrMap := make(map[string]string)
	for _, h := range headers {
		hdrMap[h] = req.Header.Get(h)
	}

	hdrMap["Host"] = req.Host
	hdrMap["HttpMethod"] = req.Method
	password, err := json.Marshal(hdrMap)
	if err != nil {
		return "", fmt.Errorf("error marshalling header map: %w", err)
	}

	return string(password), nil
}

// This method returns the AWS signer to be used for signing the request to be
// sent to Neptune Cluster.  It checks for the presence of AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN in the environment.  If not
// found, it creates a new session and gets the credentials from the session.
func getAWSRequestSigner() (*v4.Signer, error) {
	accessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	if accessKeyID != "" && secretAccessKey != "" && sessionToken != "" {
		return v4.NewSigner(credentials.NewEnvCredentials()), nil
	}

	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	return v4.NewSigner(sess.Config.Credentials), nil
}
