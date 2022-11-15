package git_collector

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

import (
	"context"
	"fmt"
	"os"

	"github.com/go-git/go-git/v5"
	. "github.com/go-git/go-git/v5/_examples"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/guacsec/guac/pkg/handler/processor"
)

const (
	CollectorGit = "GIT"
)

type GitCol struct {
	url string
	dir string
}

// RetrieveArtifacts collects the documents from the collector. It emits each collected
// document through the channel to be collected and processed by the upstream processor.
// The function should block until all the artifacts are collected and return a nil error
// or return an error from the collector crashing. This function can keep running and check
// for new artifacts as they are being uploaded by polling on an interval or run once and
// grab all the artifacts and end.
func (g *GitCol) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) {
	/*
		1. Import and get go-git
		2. Check if g.dir exists, if it doesn't clone the repo, if it does, just
		do a git reset HEAD followed by a git pull.
		3. Check for errors
		4. Create a file collector look under collector/file and pass the
		docChannel to the file collector
		5. create tests.
	*/
	// Clones the given repository, creating the remote, the local branches
	// and fetching the objects, everything in memory:
	Info("git clone https://github.com/shafeeshafee/go-test-examples")
	inMemoryStorage := memory.NewStorage()

	r, err := git.Clone(inMemoryStorage, nil, &git.CloneOptions{
		URL: "https://github.com/shafeeshafee/go-test-examples",
	})
	if err != nil {
		return
	}

	ref, err := r.Head()
	fmt.Println(ref)

	if err != nil {
		fmt.Println("There was an error cloning.")
		os.Exit(1)
		return
	}

	Info("git log")
}

// Type returns the collector type
func (g *GitCol) Type() string {
	return CollectorGit
}
