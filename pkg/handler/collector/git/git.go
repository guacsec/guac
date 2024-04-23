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
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
)

const (
	CollectorGitDocument = "GitCollector"
)

// gitDocumentCollector collects documents from a Git repository (GitHub, GitLab, etc.)
// The collector clones the repository to a local directory or pulls any updates from the repository if it has been cloned previously.
// It emits each collected document to the collector to be processed.
// The collector can either run once and grab all the artifacts or keep running and check for new artifacts based on the polling rate.
type gitDocumentCollector struct {
	url           string
	dir           string
	lastChecked   time.Time
	poll          bool
	interval      time.Duration
	fileCollector collector.Collector
}

func NewGitDocumentCollector(ctx context.Context, url string, dir string, poll bool, interval time.Duration) *gitDocumentCollector {
	fileCollector := file.NewFileCollector(ctx, dir, false, time.Second)

	return &gitDocumentCollector{
		url:           url,
		dir:           dir,
		poll:          poll,
		interval:      interval,
		fileCollector: fileCollector,
	}
}

// RetrieveArtifacts collects the documents from the collector. It emits each collected
// document through the channel to be collected and processed by the upstream processor.
// The function should block until all the artifacts are collected and return a nil error
// or return an error from the collector crashing. This function can keep running and check
// for new artifacts as they are being uploaded by polling on an interval or run once and
// grab all the artifacts and end.
func (g *gitDocumentCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	if g.poll {
		for {
			err := g.createOrPull(ctx, logger, docChannel)
			if err != nil {
				return fmt.Errorf("error creating or pulling git repo: %w", err)
			}
			g.lastChecked = time.Now()
			select {
			// If the context has been canceled it contains an err which we can throw.
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			case <-time.After(g.interval):
			}
		}
	} else {
		err := g.createOrPull(ctx, logger, docChannel)
		if err != nil {
			return fmt.Errorf("error creating or pulling git repo: %w", err)
		}
		g.lastChecked = time.Now()
	}

	return nil
}

func (g *gitDocumentCollector) createOrPull(ctx context.Context, logger *zap.SugaredLogger, docChannel chan<- *processor.Document) error {
	exists, err := checkIfDirExists(g.dir)
	if err != nil {
		return fmt.Errorf("error checking if directory exists: %w", err)
	}

	if !exists {
		if err := os.Mkdir(g.dir, os.ModePerm); err != nil {
			return fmt.Errorf("error creating directory: %w", err)
		}
		err := cloneRepoToDir(logger, g.url, g.dir)
		if err != nil {
			return fmt.Errorf("error cloning repo: %w", err)
		}
		err = g.fileCollector.RetrieveArtifacts(ctx, docChannel)
		if err != nil {
			return fmt.Errorf("error retrieving artifacts: %w", err)
		}
	} else {
		err := pullRepo(logger, g.dir)
		if err != nil && err != git.NoErrAlreadyUpToDate {
			return fmt.Errorf("error pulling repo: %w", err)
		} else if err == nil {
			err = g.fileCollector.RetrieveArtifacts(ctx, docChannel)
			if err != nil {
				return fmt.Errorf("error retrieving artifacts: %w", err)
			}
		}
	}
	return nil
}

// Type returns the collector type
func (g *gitDocumentCollector) Type() string {
	return CollectorGitDocument
}

func checkIfDirExists(name string) (bool, error) {
	_, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("error checking if directory exists: %v", err)
	}
	return true, nil
}

func cloneRepoToDir(logger *zap.SugaredLogger, url string, directory string) error {

	// Clone to directory
	logger.Debugf("git clone %s %s --recursive", url, directory)

	r, err := git.PlainClone(directory, false, &git.CloneOptions{
		URL:               url,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	})
	if err != nil {
		return fmt.Errorf("error cloning repo: %w", err)
	}

	// Retrieve the branch being pointed by HEAD
	ref, err := r.Head()
	if err != nil {
		return fmt.Errorf("error retrieving HEAD: %w", err)
	}
	// Retrieve the commit object
	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		return fmt.Errorf("error retrieving commit object: %w", err)
	}

	logger.Debugf("Commit: %s", commit)
	return nil
}

func pullRepo(logger *zap.SugaredLogger, directory string) error {
	// We instantiate a new repository targeting the given path (the .git folder)
	r, err := git.PlainOpen(directory)
	if err != nil {
		return fmt.Errorf("error opening repo: %w", err)
	}
	// Get the working directory for the repository
	w, err := r.Worktree()
	if err != nil {
		return fmt.Errorf("error getting worktree: %w", err)
	}

	// Pull the latest changes from the origin remote and merge into the current branch
	err = w.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil {
		// Only returning err and not using fmt.Errorf() because the error can be git.NoErrAlreadyUpToDate
		return err
	}

	return nil
}
