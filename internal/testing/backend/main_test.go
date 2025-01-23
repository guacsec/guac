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
	// pagination not implemented
	"TestArtifacts":                  {arango: true, redis: true, tikv: true},
	"TestBuilder":                    {arango: true, redis: true, tikv: true},
	"TestBuilders":                   {arango: true, redis: true, tikv: true},
	"TestCertifyBad":                 {arango: true, redis: true, tikv: true},
	"TestIngestCertifyBads":          {arango: true, redis: true, tikv: true},
	"TestCertifyGood":                {arango: true, redis: true, tikv: true},
	"TestIngestCertifyGoods":         {arango: true, redis: true, tikv: true},
	"TestLegal":                      {arango: true, redis: true, tikv: true},
	"TestLegals":                     {arango: true, redis: true, tikv: true},
	"TestCertifyScorecard":           {arango: true, redis: true, tikv: true},
	"TestIngestScorecards":           {arango: true, redis: true, tikv: true},
	"TestIngestCertifyVulnerability": {arango: true, redis: true, tikv: true},
	"TestIngestCertifyVulns":         {arango: true, redis: true, tikv: true},
	"TestHasMetadata":                {arango: true, redis: true, tikv: true},
	"TestIngestBulkHasMetadata":      {arango: true, redis: true, tikv: true},
	"TestIngestHasSBOMs":             {arango: true, redis: true, tikv: true},
	"TestHasSLSA":                    {arango: true, redis: true, tikv: true},
	"TestIngestHasSLSAs":             {arango: true, redis: true, tikv: true},
	"TestHasSourceAt":                {arango: true, redis: true, tikv: true},
	"TestIngestHasSourceAts":         {arango: true, redis: true, tikv: true},
	"TestHashEqual":                  {arango: true, redis: true, tikv: true},
	"TestIngestHashEquals":           {arango: true, redis: true, tikv: true},
	"TestIsDependencies":             {arango: true, redis: true, tikv: true},
	"TestIngestOccurrences":          {arango: true, redis: true, tikv: true},
	"TestLicenses":                   {arango: true, redis: true, tikv: true},
	"TestLicensesBulk":               {arango: true, redis: true, tikv: true},
	"TestIngestPkgEquals":            {arango: true, redis: true, tikv: true},
	"TestPackages":                   {arango: true, redis: true, tikv: true},
	"TestPointOfContact":             {arango: true, redis: true, tikv: true},
	"TestIngestPointOfContacts":      {arango: true, redis: true, tikv: true},
	"TestSources":                    {arango: true, redis: true, tikv: true},
	"TestIngestVulnEquals":           {arango: true, redis: true, tikv: true},
	"TestIngestVulnMetadata":         {arango: true, redis: true, tikv: true},
	"TestIngestVulnMetadatas":        {arango: true, redis: true, tikv: true},

	// arango fails IncludedOccurrences_-_Valid_Included_ID and IncludedDependencies_-_Valid_Included_ID
	"TestHasSBOM": {arango: true},
	// keyvalue: failing on dep package querying
	"TestIsDependency": {arango: true, memmap: true, redis: true, tikv: true},
	// arango errors when ID is not found
	"TestOccurrence": {arango: true},
	// keyvalue: path: input: No path found up to specified length
	// neighbors: sorting not done, testdata is only in order for arango
	"TestPath":      {memmap: true, redis: true, tikv: true},
	"TestNeighbors": {arango: true, memmap: true, redis: true, tikv: true},
	// keyvalue: query on both packages fail
	"TestPkgEqual": {arango: true, memmap: true, redis: true, tikv: true},
	// keyvalue: Query_on_OSV_and_novuln_(return_nothing_as_not_valid) fails
	// arango: errors when ID is not found
	"TestVulnEqual": {redis: true, memmap: true, tikv: true, arango: true},
	// arango: errors when ID is not found
	"TestVulnerability": {arango: true, redis: true, tikv: true},
	// redis order issues
	"TestVEX": {arango: true, redis: true, tikv: true},
	// redis order issues
	"TestVEXBulkIngest": {arango: true, redis: true},
	"TestFindSoftware":  {redis: true, arango: true},
	// remove these once its implemented for the other backends
	"TestDeleteCertifyVuln":              {arango: true, memmap: true, redis: true, tikv: true},
	"TestDeleteHasSBOM":                  {arango: true, memmap: true, redis: true, tikv: true},
	"TestDeleteHasSLSAs":                 {arango: true, memmap: true, redis: true, tikv: true},
	"TestQueryPackagesListForScan":       {arango: true, redis: true, tikv: true},
	"TestBatchQueryPkgIDCertifyVuln":     {arango: true, redis: true, tikv: true},
	"TestBatchQueryPkgIDCertifyLegal":    {arango: true, redis: true, tikv: true},
	"TestBatchQuerySubjectPkgDependency": {arango: true, redis: true, tikv: true},
	"TestBatchQueryDepPkgDependency":     {arango: true, redis: true, tikv: true},
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
