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
	"log"
	"os"

	"github.com/go-git/go-git/v5"
	. "github.com/go-git/go-git/v5/_examples"
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
	exists, err := checkIfDirExists("./temp")
	if err != nil {
		fmt.Println(err)
	}

	if !exists {
		if err := os.Mkdir("temp", os.ModePerm); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Clone a repo down: ")
		cloneRepoToTemp()
	} else {
		fmt.Println("Pull repo")
		pullRepo()
	}
}

// Type returns the collector type
func (g *GitCol) Type() string {
	return CollectorGit
}

func checkIfDirExists(name string) (bool, error) {
	if _, err := os.Stat("./temp"); os.IsNotExist(err) {
		return false, err
	} else {
		return true, err
	}
}

func cloneRepoToTemp() {
	CheckArgs("<url>", "<directory>")
	url := os.Args[1]
	directory := os.Args[2]

	// Clone to directory
	Info("git clone %s %s --recursive", url, directory)

	r, err := git.PlainClone(directory, false, &git.CloneOptions{
		URL:               url,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	})

	CheckIfError(err)

	// Retrieve the branch being pointed by HEAD
	ref, err := r.Head()
	CheckIfError(err)
	// Retrieve the commit object
	commit, err := r.CommitObject(ref.Hash())
	CheckIfError(err)

	fmt.Println("Commit: ", commit)
}

func pullRepo() {
	CheckArgs("<path>")
	path := os.Args[1]

	// We instantiate a new repository targeting the given path (the .git folder)
	r, err := git.PlainOpen(path)
	CheckIfError(err)

	// Get the working directory for the repository
	w, err := r.Worktree()
	CheckIfError(err)

	// Pull the latest changes from the origin remote and merge into the current branch
	Info("git pull origin")
	err = w.Pull(&git.PullOptions{RemoteName: "origin"})
	CheckIfError(err)

	// Print the latest commit that was just pulled
	ref, err := r.Head()
	CheckIfError(err)
	commit, err := r.CommitObject(ref.Hash())
	CheckIfError(err)

	fmt.Println(commit)
}
