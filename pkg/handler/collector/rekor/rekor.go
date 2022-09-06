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

package rekor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/sigstore/rekor-monitor/mirroring"
	"github.com/sigstore/rekor/pkg/client"
	generatedClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/util"
)

type rekorCollector struct {
	server      string
	client      *generatedClient.Rekor
	poll        bool
	interval    time.Duration
	logInfoFile string
}

func NewRekorCollector(rekorServerURL string, poll bool, interval time.Duration, logInfoFile string) (*rekorCollector, error) {
	// Get the Rekor client.
	r, err := getRekorClient(PublicRekorServerURL)
	if err != nil {
		return nil, err
	}

	var logFile string
	if logInfoFile == "" {
		logFile = logInfoFileName
	} else {
		logFile = logInfoFile
	}

	// Build a RekorCollector.
	rc := &rekorCollector{
		server:      rekorServerURL,
		client:      r,
		poll:        poll,
		interval:    interval,
		logInfoFile: logFile,
	}
	return rc, nil
}

const (
	CollectorRekor       = "rekor"
	PublicRekorServerURL = "https://rekor.sigstore.dev"
	logInfoFileName      = "logInfo.txt"
)

func Type() string {
	return CollectorRekor
}

func (rc *rekorCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	// Get all the entries since last checkpoint.
	// If there is no checkpoint, get all entries.

	sth, first, err := rc.retrieveLastCheckpoint(rc.logInfoFile)
	if err != nil {
		return err
	}

	pubkey, err := mirroring.GetPublicKey(rc.client)
	if err != nil {
		return fmt.Errorf("getting public key: %v", err)
	}

	// TODO: Verify using public key from TUF
	// Verify the checkpoint with the server's public key
	if err := mirroring.VerifySignedTreeHead(sth, pubkey); err != nil {
		return fmt.Errorf("verifying checkpoint: %v", err)
	}
	log.Printf("Current checkpoint verified - Tree Size: %d Root Hash: %s\n", sth.Size, hex.EncodeToString(sth.Hash))

	// If this is the very first snapshot within the monitor, save the snapshot
	if first {
		if err := verifySnapshot(sth, rc.logInfoFile); err != nil {
			return err
		}
	}

	// Open file to append new snapshot
	file, err := os.OpenFile(rc.logInfoFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	defer file.Close()

	for {
		// Check for root hash consistency
		newSTH, err := mirroring.VerifyLogConsistency(rc.client, int64(sth.Size), sth.Hash)
		if err != nil {
			return fmt.Errorf("failed to verify log consistency: %v", err)
		} else {
			log.Printf("Root hash consistency verified - Tree Size: %d Root Hash: %s\n", newSTH.Size, hex.EncodeToString(newSTH.Hash))
		}

		// Append new, consistency-checked snapshot
		if newSTH.Size != sth.Size {
			s, err := newSTH.SignedNote.MarshalText()
			if err != nil {
				return fmt.Errorf("failed to marshal STH: %v", err)
			}

			// Replace newlines to flatten checkpoint to single line
			if _, err := file.WriteString(fmt.Sprintf("%s\n", strings.Replace(string(s), "\n", "\\n", -1))); err != nil {
				return fmt.Errorf("failed to write to file: %v", err)
			}

			// Replace newlines to flatten checkpoint to single line
			if err := flattenCheckpoint(file, s); err != nil {
				return err
			}

			sth = newSTH

			// Convert the SignedCheckpoint to a Document.
			doc, err := rc.signedCheckpoint2Document(sth)
			if err != nil {
				return err
			}
			docChannel <- doc
		}

		// TODO: Switch to writing checkpoints to GitHub so that the history is preserved. Then we only need
		// to persist the last checkpoint.
		// Delete old checkpoints to avoid the log growing indefinitely
		if err := deleteOldCheckpoints(rc.logInfoFile); err != nil {
			log.Fatalf("failed to delete old checkpoints: %v", err)
		}

		if !rc.poll {
			return nil
		}
		time.Sleep(rc.interval)
	}
}

func (rc *rekorCollector) retrieveLastCheckpoint(logInfoFile string) (*util.SignedCheckpoint, bool, error) {
	sth := &util.SignedCheckpoint{}
	first := false

	// Try to read the file containing the previous checkpoints.
	_, err := os.Stat(logInfoFile)

	// If the file containing previous checkpoints exists.
	if err == nil {
		sth, err = readLatestCheckpoint(logInfoFile)
		if err != nil {
			return nil, false, fmt.Errorf("reading log info: %v", err)
		}
		return sth, first, nil
	}

	// Otherwise it means that no old snapshot is data available.
	if errors.Is(err, fs.ErrNotExist) {
		first = true
		// Get the latest checkpoint.
		logInfo, err := mirroring.GetLogInfo(rc.client)
		if err != nil {
			return nil, first, fmt.Errorf("getting log info: %v", err)
		}

		// Parse it.
		if err := sth.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
			return nil, first, fmt.Errorf("unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err)
		}

		return sth, first, nil
	}

	// If there is any other error while reading the file
	return nil, false, fmt.Errorf("reading %q: %v", logInfoFile, err)

}

func verifySnapshot(sth *util.SignedCheckpoint, logInfoFile string) error {
	_, err := sth.SignedNote.MarshalText()
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %v", err)
	}

	// Open file to create new snapshot
	file, err := os.OpenFile(logInfoFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	defer file.Close()

	return nil
}

func getRekorClient(rekorServerURL string) (*generatedClient.Rekor, error) {
	_, err := url.Parse(rekorServerURL)
	if err != nil {
		return nil, err
	}

	rekorClient, err := client.GetRekorClient(rekorServerURL)
	if err != nil {
		return nil, fmt.Errorf("error getting Rekor client: %v", err)
	}

	return rekorClient, nil
}

func (rc *rekorCollector) signedCheckpoint2Document(sc *util.SignedCheckpoint) (*processor.Document, error) {
	// Convert the SignedCheckpoint to bytes.
	blob, err := marshalSignedCheckpoint(sc)
	if err != nil {
		return nil, err
	}

	// Populate a Document struct.
	doc := &processor.Document{
		Blob:   blob,
		Type:   processor.DocumentITE6SLSA,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: string(CollectorRekor),
			Source:    rc.server,
		},
	}

	return doc, nil
}

func marshalSignedCheckpoint(sc *util.SignedCheckpoint) ([]byte, error) {
	var scBytes bytes.Buffer
	encoder := gob.NewEncoder(&scBytes)
	if err := encoder.Encode(sc); err != nil {
		return []byte{}, err
	}
	return scBytes.Bytes(), nil

}

// flattenCheckpoint replaces newlines to flatten checkpoint to single line
func flattenCheckpoint(file *os.File, s []byte) error {
	if _, err := file.WriteString(fmt.Sprintf("%s\n", strings.Replace(string(s), "\n", "\\n", -1))); err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}
	return nil
}

// ----------RAW COPY PASTE OF REKOR-MONITOR PRIVATE FUNCS----------------------
//
// https://github.com/sigstore/rekor-monitor/blob/686069524794e1e40624df96228241ad3f6c2cf6/cmd/mirroring/main.go

// readLatestCheckpoint reads the most recent signed checkpoint
// from the log file.
func readLatestCheckpoint(logInfoFile string) (*util.SignedCheckpoint, error) {
	// Each line in the file is one signed checkpoint
	file, err := os.Open(logInfoFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read line by line and get the last line
	scanner := bufio.NewScanner(file)
	line := ""
	for scanner.Scan() {
		line = scanner.Text()
	}

	sth := util.SignedCheckpoint{}
	if err := sth.UnmarshalText([]byte(strings.Replace(line, "\\n", "\n", -1))); err != nil {
		return nil, err
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &sth, nil
}

// deleteOldCheckpoints persists the latest 100 checkpoints. This expects that the log file
// is not being concurrently written to.
func deleteOldCheckpoints(logInfoFile string) error {
	// read all lines from file
	file, err := os.Open(logInfoFile)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	// exit early if there aren't checkpoints to truncate
	if len(lines) <= 100 {
		return nil
	}

	// open file again to overwrite
	file, err = os.OpenFile(logInfoFile, os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	for i := len(lines) - 100; i < len(lines); i++ {
		if _, err := file.WriteString(fmt.Sprintf("%s\n", lines[i])); err != nil {
			return err
		}
	}

	return nil
}
