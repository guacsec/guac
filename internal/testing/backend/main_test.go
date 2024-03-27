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
	// arango fails IncludedOccurrences_-_Valid_Included_ID and IncludedDependencies_-_Valid_Included_ID
	"TestHasSBOM": {arango: true},
	// keyvalue: failing on dep package querying
	"TestIsDependency": {memmap: true, redis: true, tikv: true},
	// arango errors when ID is not found
	"TestOccurrence": {arango: true},
	// ent: Path/Nodes/Neighbors not implemented
	// keyvalue: path: input: No path found up to specified length
	// neighbors: sorting not done, testdata is only in order for arango
	"TestPath":      {ent: true, memmap: true, redis: true, tikv: true},
	"TestNodes":     {ent: true},
	"TestNeighbors": {ent: true, memmap: true, redis: true, tikv: true},
	// ent: Query_on_both_pkgs fails
	// keyvalue: query on both packages fail
	"TestPkgEqual": {ent: true, memmap: true, redis: true, tikv: true},
	// ent: Query_on_vulnerability_IDs fails
	// keyvalue: Query_on_OSV_and_novuln_(return_nothing_as_not_valid) fails
	// arango: errors when ID is not found
	"TestVulnEqual": {memmap: true, redis: true, tikv: true, arango: true},
	// arango: errors when ID is not found
	// ent: query by novuln fails, query by ID fails
	"TestVulnerability": {arango: true},
	// redis order issues
	"TestVEX": {redis: true},
	// redis order issues
	"TestVEXBulkIngest": {redis: true},
	"TestFindSoftware":  {ent: true, redis: true, arango: true},
}

type backend interface {
	Setup() error
	Get() backends.Backend
	Clear() error
	Cleanup()
}

var testBackends = map[string]backend{
	// memmap: newMemMap(),
	// arango: newArango(),
	// redis:  newRedis(),
	ent: newEnt(),
	// tikv:   newTikv(),
}

var currentBackend string

func TestMain(m *testing.M) {
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
