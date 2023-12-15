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

//go:build integration

package backend_test

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends"
)

const (
	memmap = "memmap"
	arango = "arango"
	redis  = "redis"
	ent    = "ent"
	tikv   = "tikv"
)

var skipMatrix = map[string]map[string]bool{
	// Just some examples here
	"TestPkg":       {arango: true},
	"TestArtifacts": {memmap: true},
	"TestBuilder":   {arango: true, memmap: true},
	// "TestCertifyBad":          {arango: true},
	// "TestIngestCertifyBads":   {arango: true},
	"TestCertifyBadNeighbors": {arango: true},
}

type backend interface {
	Setup() error
	Get() backends.Backend
	Clear() error
	Cleanup()
}

var testBackends = map[string]backend{
	memmap: newMemMap(),
	arango: newArango(),
	redis:  newRedis(),
	ent:    newEnt(),
	tikv:   newTikv(),
}

var currentBackend string

func TestMain(m *testing.M) {
	setupOpts()
	var rv int
	for beName, be := range testBackends {
		currentBackend = beName
		if err := be.Setup(); err != nil {
			fmt.Printf("Could not setup backend %q, err: %s\n", currentBackend, err)
			rv = 1
			continue
		}
		fmt.Printf("Testing backend %q\n", currentBackend)
		start := time.Now()
		code := m.Run()
		end := time.Now()
		if code != 0 {
			rv = code
		}
		be.Cleanup()
		fmt.Printf("Backend %q done in %06.3fs\n", currentBackend, end.Sub(start).Seconds())
	}
	os.Exit(rv)
}

func setupTest(t *testing.T) backends.Backend {
	t.Helper()
	checkSkip(t)
	be := testBackends[currentBackend]
	t.Cleanup(func() {
		if err := be.Clear(); err != nil {
			t.Fatalf("Error clearing backend %q between tests: %s", currentBackend, err)
		}
	})
	return be.Get()
}

func checkSkip(t *testing.T) {
	t.Helper()
	pc, _, _, ok := runtime.Caller(2) // setupTest -> checkSkip
	if !ok {
		t.Fatal("Could not get caller")
	}
	f := runtime.FuncForPC(pc)
	funcName := trimFuncName(f.Name())
	if skipMatrix[funcName] != nil {
		if skipMatrix[funcName][currentBackend] {
			t.Skip()
		}
	}
}

func trimFuncName(fullName string) string {
	parts := strings.Split(fullName, ".")
	return parts[len(parts)-1]
}
