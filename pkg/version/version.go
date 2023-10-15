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

package version

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/logging"
)

var (
	Version      = "v0.0.1-custom"
	Commit, Date string
	UserAgent    string
	UATransport  http.RoundTripper
)

type uat struct {
	tr http.RoundTripper
}

func init() {
	UserAgent = fmt.Sprintf("GUAC/%s", Version)
	UATransport = uat{tr: http.DefaultTransport}
}

func (u uat) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("User-Agent", UserAgent)
	return u.tr.RoundTrip(r)
}

// DumpVersion dumps the version information to the log.
func DumpVersion() {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)
	if Commit == "" {
		commit, _ := exec.Command("git", "rev-parse", "HEAD").Output()
		Commit = strings.TrimRight(string(commit), "\n")
		logger.Infof("Commit: dev-%s", Commit)
	} else {
		logger.Infof("Commit: %s", Commit)
	}

	if Date == "" {
		Date = time.Now().Format("2006-01-02")
		logger.Infof("Date: %s", Date)
	} else {
		logger.Infof("Date: %s", Date)
	}
}
