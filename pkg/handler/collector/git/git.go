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

package git_collector

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
)

const (
	CollectorGit = "GIT"
)

type gitCol struct {
	url         string
	dir         string
	lastChecked time.Time
	poll        bool
	interval    time.Duration
}

func NewGitCol(ctx context.Context, url string, dir string, poll bool, interval time.Duration) *gitCol {
	return &gitCol{
		url:      url,
		dir:      dir,
		poll:     poll,
		interval: interval,
	}
}

// RetrieveArtifacts collects the documents from the collector. It emits each collected
// document through the channel to be collected and processed by the upstream processor.
// The function should block until all the artifacts are collected and return a nil error
// or return an error from the collector crashing. This function can keep running and check
// for new artifacts as they are being uploaded by polling on an interval or run once and
// grab all the artifacts and end.
func (g *gitCol) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	if g.poll {
		for {
			if ctx.Err() != nil {
				return nil
			}
			err := createOrPull(logger, g.url, g.dir)
			if err != nil {
				return err
			}
			g.lastChecked = time.Now()
			time.Sleep(g.interval)
		}
	} else {
		err := createOrPull(logger, g.url, g.dir)
		if err != nil {
			return err
		}
		g.lastChecked = time.Now()
	}

	return nil
}

func createOrPull(logger *zap.SugaredLogger, url string, directory string) error {
	exists := checkIfDirExists(directory)

	if !exists {
		if err := os.Mkdir(directory, os.ModePerm); err != nil {
			logger.Fatal(err)
		}
		fmt.Println("Clone a repo down: ")
		err := cloneRepoToTemp(logger, url, directory)
		if err != nil {
			return err
		}
	} else {
		fmt.Println("Pull repo")
		err := pullRepo(logger, directory)
		if err != nil {
			return err
		}
	}
	return nil
}

// Type returns the collector type
func (g *gitCol) Type() string {
	return CollectorGit
}

func checkIfDirExists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

func cloneRepoToTemp(logger *zap.SugaredLogger, url string, directory string) error {

	// Clone to directory
	logger.Infof("git clone %s %s --recursive", url, directory)

	r, err := git.PlainClone(directory, false, &git.CloneOptions{
		URL:               url,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	})
	if err != nil {
		return err
	}

	// Retrieve the branch being pointed by HEAD
	ref, err := r.Head()
	if err != nil {
		return err
	}
	// Retrieve the commit object
	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		return err
	}

	logger.Infof("Commit: %s", commit)
	return nil
}

func pullRepo(logger *zap.SugaredLogger, directory string) error {
	// We instantiate a new repository targeting the given path (the .git folder)
	r, err := git.PlainOpen(directory)
	if err != nil {
		return err
	}
	// Get the working directory for the repository
	w, err := r.Worktree()
	if err != nil {
		return err
	}

	// Pull the latest changes from the origin remote and merge into the current branch
	logger.Info("git pull origin")
	err = w.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return err
	}

	// Print the latest commit that was just pulled
	ref, err := r.Head()
	if err != nil {
		return err
	}
	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		return err
	}

	logger.Info(commit)
	return nil
}
