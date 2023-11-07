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

package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	gqlDefaultServerURL = "http://localhost:8080/query"
	httpTimeout         = 10 * time.Second
	guacType            = "guac"
	noVulnType          = "novuln"
)

func main() {
	if os.Getenv("GUAC_EXPERIMENTAL") != "true" {
		log.Fatalf("GUAC_EXPERIMENTAL is not set to true. Exiting.")
	}

	r := gin.Default()
	ctx := context.Background()

	r.GET("/known/package/*hash", packageHandlerForHash(ctx))
	r.GET("/known/source/*vcs", sourceHandlerForVCS(ctx))
	r.GET("/known/artifact/*artifact", artifactHandlerForArtifact(ctx))
	r.GET("/vuln/*purl", vulnerabilityHandler(ctx))
	r.GET("/bad", badHandler(ctx))

	if err := r.Run(":9000"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

func removeDuplicateValuesFromPath(path []string) []string {
	keys := make(map[string]bool)
	var list []string

	for _, entry := range path {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
