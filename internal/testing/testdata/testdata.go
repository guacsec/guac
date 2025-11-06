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

package testdata

import (
	_ "embed"
	"encoding/base64"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/guacsec/guac/internal/testing/keyutil"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	asmhelpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	jsoniter "github.com/json-iterator/go"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

var (
	// based off https://github.com/spdx/spdx-examples/blob/master/example7/spdx/example7-third-party-modules.spdx.json
	//go:embed exampledata/small-spdx.json
	SpdxExampleSmall []byte

	//go:embed exampledata/alpine-spdx.json
	SpdxExampleBig []byte

	//go:embed exampledata/alpine-small-spdx.json
	SpdxExampleAlpine []byte

	// Invalid types for field spdxVersion
	//go:embed exampledata/invalid-spdx.json
	SpdxInvalidExample []byte

	// Invalid SPDXIdentifier document
	//go:embed exampledata/invalid-spdx-identifier-spdx.json
	SpdxInvalidSPDXIdentifierExample []byte

	// Example scorecard
	//go:embed exampledata/kubernetes-scorecard.json
	ScorecardExample []byte

	// Invalid scorecard
	//go:embed exampledata/invalid-scorecard.json
	ScorecardInvalid []byte

	//go:embed exampledata/alpine-cyclonedx.json
	CycloneDXExampleAlpine []byte

	//go:embed exampledata/quarkus-deps-cyclonedx.json
	CycloneDXExampleQuarkusDeps []byte

	//go:embed exampledata/small-deps-cyclonedx.json
	CycloneDXExampleSmallDeps []byte

	//go:embed exampledata/invalid-cyclonedx.json
	CycloneDXInvalidExample []byte

	//go:embed exampledata/distroless-cyclonedx.json
	CycloneDXDistrolessExample []byte

	//go:embed exampledata/distroless-cyclonedx-invalid-version.json
	CycloneDXDistrolessInvalidVersionExample []byte

	//go:embed exampledata/busybox-cyclonedx.json
	CycloneDXBusyboxExample []byte

	//go:embed exampledata/busybox-cyclonedx.json.bz2
	CycloneDXBz2Example []byte

	//go:embed exampledata/busybox-cyclonedx.json.zst
	CycloneDXZstdExample []byte

	//go:embed exampledata/big-mongo-cyclonedx.json
	CycloneDXBigExample []byte

	//go:embed exampledata/cdx-v1.4.json
	CycloneDXVersion1_4 []byte

	//go:embed exampledata/npm-cyclonedx-dependencies-missing-depends-on.json
	CycloneDXDependenciesMissingDependsOn []byte

	//go:embed exampledata/laravel-cyclonedx.xml
	CycloneDXExampleLaravelXML []byte

	//go:embed exampledata/invalid-cyclonedx.xml
	CycloneDXInvalidExampleXML []byte

	//go:embed exampledata/no-dependent-components-cyclonedx.json
	CycloneDXExampleNoDependentComponents []byte

	//go:embed exampledata/cyclonedx-no-top-level.json
	CycloneDXExampleNoTopLevelComp []byte

	//go:embed exampledata/cyclonedx-unaffected-vex.json
	CycloneDXVEXUnAffected []byte

	//go:embed exampledata/cyclonedx-vex-affected.json
	CycloneDXVEXAffected []byte

	//go:embed exampledata/cyclonedx-vex-no-analysis.json
	CycloneDXVEXWithoutAnalysis []byte

	//go:embed exampledata/cyclonedx-vex-resolved-with-pedigree.json
	CycloneDXVEXResolvedWithPedigree []byte

	//go:embed exampledata/cyclonedx-vex-false-positive.json
	CycloneDXVEXFalsePositive []byte

	//go:embed exampledata/cyclonedx-vex.xml
	CyloneDXVEXExampleXML []byte

	//go:embed exampledata/xray-cdx-vulns.json
	CyloneDXXRAYExampleVulns []byte

	//go:embed exampledata/crev-review.json
	ITE6CREVExample []byte

	//go:embed exampledata/github-review.json
	ITE6ReviewExample []byte

	//go:embed exampledata/certify-vuln.json
	ITE6VulnExample []byte

	//go:embed exampledata/cd-log4j.json
	ITE6CDLog4j []byte

	//go:embed exampledata/cd-source-log4j.json
	ITE6CDSourceLog4j []byte

	//go:embed exampledata/cd-common-text.json
	ITE6CDCommonText []byte

	//go:embed exampledata/cd-source-common-text.json
	ITE6CDSourceCommonText []byte

	//go:embed exampledata/certify-novuln.json
	ITE6NoVulnExample []byte

	//go:embed exampledata/oci-kubectl-linux-amd64-in-toto.json
	OCIKubectlLinuxAMD64ITE6 []byte

	//go:embed exampledata/oci-kubectl-linux-amd64-spdx.json
	OCIKubectlLinuxAMD64SPDX []byte

	//go:embed exampledata/oci-kubectl-linux-amd64-spdx-1.json
	OCIKubectlLinuxAMD64SPDX1 []byte

	//go:embed exampledata/oci-kubectl-linux-arm-v7-in-toto.json
	OCIKubectlLinuxARMV7ITE6 []byte

	//go:embed exampledata/oci-kubectl-linux-arm-v7-spdx.json
	OCIKubectlLinuxARMV7SPDX []byte

	//go:embed exampledata/oci-kubectl-linux-arm64-in-toto.json
	OCIKubectlLinuxARM64ITE6 []byte

	//go:embed exampledata/oci-kubectl-linux-arm64-spdx.json
	OCIKubectlLinuxARM64SPDX []byte

	//go:embed exampledata/oci-kubectl-linux-arm64-spdx-1.json
	OCIKubectlLinuxARM64SPDX1 []byte

	//go:embed exampledata/oci-kubectl-windows-amd64-in-toto.json
	OCIKubectlWindowsAMD64ITE6 []byte

	//go:embed exampledata/oci-dsse-att.json
	OCIDsseAttExample []byte

	//go:embed exampledata/oci-spdx.json
	OCISPDXExample []byte

	//go:embed exampledata/go-spdx-multi-arch_1.json
	OCIGoSPDXMulti1 []byte

	//go:embed exampledata/go-spdx-multi-arch_2.json
	OCIGoSPDXMulti2 []byte

	//go:embed exampledata/go-spdx-multi-arch_3.json
	OCIGoSPDXMulti3 []byte

	//go:embed exampledata/ingest_predicates.json
	IngestPredicatesExample []byte

	//go:embed exampledata/small-legal-cyclonedx.json
	CycloneDXLegalExample []byte

	//go:embed exampledata/small-legal-cyclonedx-no-inline.json
	CycloneDXLegalNoInlineExample []byte

	//go:embed exampledata/cyclonedx-components-nested.json
	CycloneDXComponentsNested []byte

	//go:embed exampledata/cyclonedx-components-flat.json
	CycloneDXComponentsFlat []byte

	//go:embed exampledata/eol-all.json
	EOLAll []byte

	//go:embed exampledata/eol-sapmachine.json
	EOLSapMachine []byte

	// json format
	json = jsoniter.ConfigCompatibleWithStandardLibrary
	// CycloneDX VEX testdata unaffected
	pkg, _   = asmhelpers.PurlToPkg("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0?type=jar")
	vulnSpec = &generated.VulnerabilityInputSpec{
		Type:            "cve",
		VulnerabilityID: "cve-2020-25649",
	}
	CycloneDXUnAffectedVexIngest = []assembler.VexIngest{
		{
			Pkg:           pkg,
			Vulnerability: vulnSpec,
			VexData: &generated.VexStatementInputSpec{
				Status:           generated.VexStatusNotAffected,
				VexJustification: generated.VexJustificationVulnerableCodeNotInExecutePath,
				Statement:        "com.fasterxml.jackson.core:jackson-databind is a library which contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor.\n\nAffected versions of this package are vulnerable to XML External Entity (XXE) Injection. A flaw was found in FasterXML Jackson Databind, where it does not have entity expansion secured properly in the DOMDeserializer class. The highest threat from this vulnerability is data integrity.",
				StatusNotes:      "Automated dataflow analysis and manual code review indicates that the vulnerable code is not reachable, either directly or indirectly.",
				KnownSince:       parseUTCTime("2020-12-03T00:00:00.000Z"),
			},
		},
	}
	CycloneDXUnAffectedVulnMetadata = []assembler.VulnMetadataIngest{
		{
			Vulnerability: vulnSpec,
			VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
				ScoreType:  generated.VulnerabilityScoreTypeCvssv31,
				ScoreValue: 7.5,
				Timestamp:  parseUTCTime("2020-12-03T00:00:00.000Z"),
			},
		},
		{
			Vulnerability: vulnSpec,
			VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
				ScoreType:  generated.VulnerabilityScoreTypeCvssv31,
				ScoreValue: 8.2,
				Timestamp:  parseUTCTime("2020-12-03T00:00:00.000Z"),
			},
		},
		{
			Vulnerability: vulnSpec,
			VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
				ScoreType:  generated.VulnerabilityScoreTypeCvssv31,
				ScoreValue: 0.0,
				Timestamp:  parseUTCTime("2020-12-03T00:00:00.000Z"),
			},
		},
	}
	CycloneDXUnAffectedPredicates = assembler.IngestPredicates{
		VulnMetadata: CycloneDXUnAffectedVulnMetadata,
		Vex:          CycloneDXUnAffectedVexIngest,
	}

	// CycloneDX VEX testdata affected packages.
	VulnSpecAffected = &generated.VulnerabilityInputSpec{
		Type:            "cve",
		VulnerabilityID: "cve-2021-44228",
	}
	VexDataAffected = &generated.VexStatementInputSpec{
		Status:           generated.VexStatusAffected,
		VexJustification: generated.VexJustificationNotProvided,
		Statement:        "",
		StatusNotes:      "Versions of Product ABC are affected by the vulnerability. Customers are advised to upgrade to the latest release.",
		KnownSince:       time.Unix(0, 0).UTC(),
	}
	VexDataNoAnalysis = &generated.VexStatementInputSpec{
		Status:           generated.VexStatusAffected,
		VexJustification: generated.VexJustificationNotProvided,
		Statement:        "com.fasterxml.jackson.core:jackson-databind is a library which contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor.\n\nAffected versions of this package are vulnerable to XML External Entity (XXE) Injection. A flaw was found in FasterXML Jackson Databind, where it does not have entity expansion secured properly in the DOMDeserializer class. The highest threat from this vulnerability is data integrity.",
		StatusNotes:      "",
		KnownSince:       time.Unix(0, 0).UTC(),
	}
	CycloneDXAffectedVulnMetadata = []assembler.VulnMetadataIngest{
		{
			Vulnerability: VulnSpecAffected,
			VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
				ScoreType:  generated.VulnerabilityScoreTypeCvssv31,
				ScoreValue: 10,
				Timestamp:  time.Unix(0, 0).UTC(),
			},
		},
	}
	CycloneDXNoAnalysisVulnMetadata = []assembler.VulnMetadataIngest{
		{
			Vulnerability: VulnSpecAffected,
			VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
				ScoreType:  generated.VulnerabilityScoreTypeCvssv31,
				ScoreValue: 10,
				Timestamp:  time.Unix(0, 0).UTC(),
			},
		},
	}
	// VexData for resolved_with_pedigree status (maps to VexStatusFixed)
	VexDataResolvedWithPedigree = &generated.VexStatementInputSpec{
		Status:           generated.VexStatusFixed,
		VexJustification: generated.VexJustificationNotProvided,
		Statement:        "",
		StatusNotes:      "Vulnerability has been remediated with evidence provided in component pedigree",
		KnownSince:       time.Unix(0, 0).UTC(),
	}
	// VexData for false_positive status (maps to VexStatusNotAffected)
	VexDataFalsePositive = &generated.VexStatementInputSpec{
		Status:           generated.VexStatusNotAffected,
		VexJustification: generated.VexJustificationNotProvided,
		Statement:        "",
		StatusNotes:      "Vulnerability was falsely identified or associated with this component",
		KnownSince:       time.Unix(0, 0).UTC(),
	}
	// Vulnerability specs for new test cases
	VulnSpecResolvedWithPedigree = &generated.VulnerabilityInputSpec{
		Type:            "cve",
		VulnerabilityID: "cve-2024-0001",
	}
	VulnSpecFalsePositive = &generated.VulnerabilityInputSpec{
		Type:            "cve",
		VulnerabilityID: "cve-2024-0002",
	}
	// VulnMetadata for resolved_with_pedigree test
	CycloneDXResolvedWithPedigreeVulnMetadata = []assembler.VulnMetadataIngest{
		{
			Vulnerability: VulnSpecResolvedWithPedigree,
			VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
				ScoreType:  generated.VulnerabilityScoreTypeCvssv31,
				ScoreValue: 7.5,
				Timestamp:  time.Unix(0, 0).UTC(),
			},
		},
	}
	// VulnMetadata for false_positive test
	CycloneDXFalsePositiveVulnMetadata = []assembler.VulnMetadataIngest{
		{
			Vulnerability: VulnSpecFalsePositive,
			VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
				ScoreType:  generated.VulnerabilityScoreTypeCvssv31,
				ScoreValue: 6.0,
				Timestamp:  time.Unix(0, 0).UTC(),
			},
		},
	}

	topLevelPkg, _     = asmhelpers.PurlToPkg("pkg:guac/cdx/ABC")
	HasSBOMVexAffected = []assembler.HasSBOMIngest{
		{
			Pkg: topLevelPkg,
			HasSBOM: &model.HasSBOMInputSpec{
				Algorithm:  "sha256",
				Digest:     "eb62836ed6339a2d57f66d2e42509718fd480a1befea83f925e918444c369114",
				KnownSince: parseRfc3339("2022-03-03T00:00:00Z"),
			},
		},
	}
	HasSBOMVexNoAnalysis = []assembler.HasSBOMIngest{
		{
			Pkg: topLevelPkg,
			HasSBOM: &model.HasSBOMInputSpec{
				Algorithm:  "sha256",
				Digest:     "265c99f1f9a09b7fc10c14c97ca1a07fc52ae470f5cbcddd9baf5585fb28221c",
				KnownSince: parseRfc3339("2022-03-03T00:00:00Z"),
			},
		},
	}
	// HasSBOM for resolved_with_pedigree test
	topLevelPkgResolvedWithPedigree, _ = asmhelpers.PurlToPkg("pkg:guac/cdx/test-app@1.0.0")
	HasSBOMVexResolvedWithPedigree     = []assembler.HasSBOMIngest{
		{
			Pkg: topLevelPkgResolvedWithPedigree,
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:        "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
				Algorithm:  "sha256",
				Digest:     "a9e5e5fcc0939b4e9ddf74a5863ff577bef9bbf8086d99a4dafb8154c451b56f",
				KnownSince: parseRfc3339("2024-01-15T10:30:00Z"),
			},
		},
	}
	// HasSBOM for false_positive test
	topLevelPkgFalsePositive, _ = asmhelpers.PurlToPkg("pkg:guac/cdx/test-app-2@1.0.0")
	HasSBOMVexFalsePositive     = []assembler.HasSBOMIngest{
		{
			Pkg: topLevelPkgFalsePositive,
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:        "urn:uuid:4e671687-395b-41f5-a30f-a58921a69b80",
				Algorithm:  "sha256",
				Digest:     "738690dd4acaf82b417072354ee631a20a50453278053b558770c6f65906f11d",
				KnownSince: parseRfc3339("2024-01-15T10:30:00Z"),
			},
		},
	}
	// Predicates for resolved_with_pedigree test
	// The affects ref is "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79/1#test-component"
	// The parser splits on "#" and uses "test-component" as pkdIdentifier
	// Then creates PURL as pkg:guac/pkg/test-component@1.0.0 using guacCDXPkgPurl
	resolvedWithPedigreePkg, _             = asmhelpers.PurlToPkg("pkg:guac/pkg/test-component@1.0.0")
	CycloneDXResolvedWithPedigreeVexIngest = []assembler.VexIngest{
		{
			Pkg:           resolvedWithPedigreePkg,
			Vulnerability: VulnSpecResolvedWithPedigree,
			VexData:       VexDataResolvedWithPedigree,
		},
	}
	CycloneDXResolvedWithPedigreePredicates = assembler.IngestPredicates{
		HasSBOM:      HasSBOMVexResolvedWithPedigree,
		VulnMetadata: CycloneDXResolvedWithPedigreeVulnMetadata,
		Vex:          CycloneDXResolvedWithPedigreeVexIngest,
		// Note: No CertifyVuln because status is Fixed (not Affected/UnderInvestigation)
	}
	// Predicates for false_positive test
	// The affects ref is "urn:uuid:4e671687-395b-41f5-a30f-a58921a69b80/1#test-component-2"
	// The parser splits on "#" and uses "test-component-2" as pkdIdentifier
	// Then creates PURL as pkg:guac/pkg/test-component-2@1.0.0 using guacCDXPkgPurl
	falsePositivePkg, _             = asmhelpers.PurlToPkg("pkg:guac/pkg/test-component-2@1.0.0")
	CycloneDXFalsePositiveVexIngest = []assembler.VexIngest{
		{
			Pkg:           falsePositivePkg,
			Vulnerability: VulnSpecFalsePositive,
			VexData:       VexDataFalsePositive,
		},
	}
	CycloneDXFalsePositivePredicates = assembler.IngestPredicates{
		HasSBOM:      HasSBOMVexFalsePositive,
		VulnMetadata: CycloneDXFalsePositiveVulnMetadata,
		Vex:          CycloneDXFalsePositiveVexIngest,
		// Note: No CertifyVuln because status is NotAffected (not Affected/UnderInvestigation)
	}

	// DSSE/SLSA Testdata

	// Taken from: https://slsa.dev/provenance/v0.2#example
	ite6SLSA02 = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "helloworld", "digest": {"sha256": "3a2bd2c5cc4c978e8aefd8bd0ef335fb42ee31d1"}}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"builder": { "id": "https://github.com/Attestations/GitHubHostedActions@v1" },
			"buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			"invocation": {
			  "configSource": {
				"uri": "git+https://github.com/curl/curl-docker@master",
				"digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" },
				"entryPoint": "build.yaml:maketgz"
			  }
			},
			"metadata": {
			  "buildStartedOn": "2020-08-19T08:38:00Z",
			  "completeness": {
				  "environment": true
			  }
			},
			"materials": [
			  {
				"uri": "git+https://github.com/curl/curl-docker@master",
				"digest": { "sha1": "24279c5185ddc042896e3748f47fa89b48c1c14e" }
			  }, {
				"uri": "github_hosted_vm:ubuntu-18.04:20210123.1",
				"digest": { "sha1": "0bcaaa161e719bca41b6d33fc02547c0f97d5397" }
			  }
			]
		}
	}`

	ite6SLSA1 = `
{
    "_type": "https://in-toto.io/Statement/v1",
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
            "externalParameters": {
                "inputs": {
                    "build_id": 123456768,
                    "deploy_target": "deployment_sys_1a",
                    "perform_deploy": "true"
                },
                "vars": {
                    "MASCOT": "Mona"
                },
                "workflow": {
                    "ref": "refs/heads/main",
                    "repository": "https://github.com/octocat/hello-world",
                    "path": ".github/workflow/release.yml"
                }
            },
            "internalParameters": {
                "github": {
                    "actor_id": "1234567",
                    "event_name": "workflow_dispatch"
                }
            },
            "resolvedDependencies": [
                {
                    "uri": "git+https://github.com/octocat/hello-world@refs/heads/main",
                    "digest": {
                        "gitCommit": "c27d339ee6075c1f744c5d4b200f7901aad2c369"
                    }
                 },
                {
                    "uri": "https://github.com/actions/virtual-environments/releases/tag/ubuntu20/20220515.1"
                }
            ]
        },
        "runDetails": {
            "builder": {
                "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v0.0.1"
            },
            "metadata": {
                "invocationId": "https://github.com/octocat/hello-world/actions/runs/1536140711/attempts/1",
                "startedOn": "2023-01-01T12:34:56Z"
            }
        }
    },
    "subject": [
        {
            "name": "_",
            "digest": {
                "sha256": "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4"
            }
        }
    ]
}
`

	ite6SLSA1_2 = `
{
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
        {
            "name": "sigstore",
            "uri": "pkg:npm/sigstore/sigstore-js@4.2.0",
            "digest": {
                "sha1": "428601801d1f5d105351a403f58c38269de93f680"
            }
        }
    ],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://github.com/npm/cli/gha/v2",
            "resolved_dependencies": [
                {
                    "uri": "pkg:npm/sigstore/segs@1.2.0",
                    "digest": {
                        "sha1": "5b8c0801d1f5d105351a403f58c38269de93f680"
                    }
                }
            ]
        },
        "runDetails": {
            "builder": {
                "id": "https://github.com/actions/runner"
            },
            "metadata": {
                "invocationId": "b6186090-c8ff-4f91-97cf-7a3b47699e57",
                "startedOn": "2022-05-24T12:13:35.054695403Z"
            }
        }
    }
}`

	Ite6SLSA1Doc = processor.Document{
		Blob:   []byte(ite6SLSA1),
		Type:   processor.DocumentITE6SLSA,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}

	Ite6SLSA1Doc_2 = processor.Document{
		Blob:   []byte(ite6SLSA1_2),
		Type:   processor.DocumentITE6SLSA,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}

	b64ITE6SLSA    = base64.StdEncoding.EncodeToString([]byte(ite6SLSA02))
	Ite6Payload, _ = json.Marshal(dsse.Envelope{
		PayloadType: "https://in-toto.io/Statement/v0.1",
		Payload:     b64ITE6SLSA,
		Signatures: []dsse.Signature{{
			KeyID: "id1",
			Sig:   "test",
		}},
	})
	Ite6DSSEDoc = processor.Document{
		Blob:   Ite6Payload,
		Type:   processor.DocumentDSSE,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	Ite6SLSADoc = processor.Document{
		Blob:   []byte(ite6SLSA02),
		Type:   processor.DocumentITE6SLSA,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}

	art = model.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "3a2bd2c5cc4c978e8aefd8bd0ef335fb42ee31d1",
	}

	artPkg, _ = asmhelpers.PurlToPkg(asmhelpers.GuacGenericPurl("helloworld"))

	mat1 = model.ArtifactInputSpec{
		Algorithm: "sha1",
		Digest:    "24279c5185ddc042896e3748f47fa89b48c1c14e",
	}

	mat1Src, _ = asmhelpers.VcsToSrc("git+https://github.com/curl/curl-docker@master")

	mat2 = model.ArtifactInputSpec{
		Algorithm: "sha1",
		Digest:    "0bcaaa161e719bca41b6d33fc02547c0f97d5397",
	}

	mat2Pkg, _ = asmhelpers.PurlToPkg(asmhelpers.GuacGenericPurl("github_hosted_vm:ubuntu-18.04:20210123.1"))

	build = model.BuilderInputSpec{
		Uri: "https://github.com/Attestations/GitHubHostedActions@v1",
	}

	EcdsaPubKey, pemBytes, _ = keyutil.GetECDSAPubKey()
	// Not currently used due to skipping of DSSE and Trust information
	// keyHash, _               = dsse.SHA256KeyID(EcdsaPubKey)
	// Ident = assembler.IdentityNode{
	// 	ID:        "test",
	// 	Digest:    keyHash,
	// 	Key:       base64.StdEncoding.EncodeToString(pemBytes),
	// 	KeyType:   "ecdsa",
	// 	KeyScheme: "ecdsa",
	// 	NodeData: *assembler.NewObjectMetadata(
	// 		processor.SourceInformation{
	// 			Collector: "TestCollector",
	// 			Source:    "TestSource",
	// 		},
	// 	),
	// }

	slsaIsOccurrence = model.IsOccurrenceInputSpec{
		Justification: "from SLSA definition of checksums for subject/materials",
	}

	slsaStartTime, _ = time.Parse(time.RFC3339, "2020-08-19T08:38:00Z")
	SlsaPreds        = assembler.IngestPredicates{
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{Pkg: artPkg, Artifact: &art, IsOccurrence: &slsaIsOccurrence},
			{Src: mat1Src, Artifact: &mat1, IsOccurrence: &slsaIsOccurrence},
			{Pkg: mat2Pkg, Artifact: &mat2, IsOccurrence: &slsaIsOccurrence},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "https://github.com/Attestations/GitHubActionsWorkflow@v1",
					SlsaVersion: "https://slsa.dev/provenance/v0.2",
					StartedOn:   &slsaStartTime,
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.metadata.completeness.environment", Value: "true"},
						{Key: "slsa.metadata.buildStartedOn", Value: "2020-08-19T08:38:00Z"},
						{Key: "slsa.metadata.completeness.materials", Value: "false"},
						{Key: "slsa.buildType", Value: "https://github.com/Attestations/GitHubActionsWorkflow@v1"},
						{Key: "slsa.invocation.configSource.entryPoint", Value: "build.yaml:maketgz"},
						{Key: "slsa.invocation.configSource.uri", Value: "git+https://github.com/curl/curl-docker@master"},
						{Key: "slsa.metadata.reproducible", Value: "false"},
						{Key: "slsa.materials.0.uri", Value: "git+https://github.com/curl/curl-docker@master"},
						{Key: "slsa.builder.id", Value: "https://github.com/Attestations/GitHubHostedActions@v1"},
						{Key: "slsa.invocation.configSource.digest.sha1", Value: "d6525c840a62b398424a78d792f457477135d0cf"},
						{Key: "slsa.metadata.completeness.parameters", Value: "false"},
						{Key: "slsa.materials.0.digest.sha1", Value: "24279c5185ddc042896e3748f47fa89b48c1c14e"},
						{Key: "slsa.materials.1.uri", Value: "github_hosted_vm:ubuntu-18.04:20210123.1"},
						{Key: "slsa.materials.1.digest.sha1", Value: "0bcaaa161e719bca41b6d33fc02547c0f97d5397"},
					},
				},
				Artifact:  &art,
				Builder:   &build,
				Materials: []model.ArtifactInputSpec{mat1, mat2},
			},
		},
	}

	slsa1time, _ = time.Parse(time.RFC3339, "2023-01-01T12:34:56Z")
	SlsaPreds1   = assembler.IngestPredicates{
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Src: &model.SourceInputSpec{
					Type:      "git",
					Namespace: "github.com/octocat/hello-world@refs/heads",
					Name:      "main",
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "gitCommit",
					Digest:    "c27d339ee6075c1f744c5d4b200f7901aad2c369",
				},
				IsOccurrence: &slsaIsOccurrence,
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "guac",
					Namespace: ptrfrom.String("generic"),
					Name:      "_",
					Version:   ptrfrom.String(""),
					Subpath:   ptrfrom.String(""),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "sha256",
					Digest:    "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
				},
				IsOccurrence: &slsaIsOccurrence,
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "sha256",
					Digest:    "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v0.0.1",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "gitCommit",
					Digest:    "c27d339ee6075c1f744c5d4b200f7901aad2c369",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
					SlsaVersion: "https://slsa.dev/provenance/v1",
					StartedOn:   &slsa1time,
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.buildDefinition.buildType", Value: "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"},
						{Key: "slsa.buildDefinition.externalParameters.inputs.build_id", Value: "1.23456768e+08"},
						{Key: "slsa.buildDefinition.externalParameters.inputs.deploy_target", Value: "deployment_sys_1a"},
						{Key: "slsa.buildDefinition.externalParameters.inputs.perform_deploy", Value: "true"},
						{Key: "slsa.buildDefinition.externalParameters.vars.MASCOT", Value: "Mona"},
						{Key: "slsa.buildDefinition.externalParameters.workflow.path", Value: ".github/workflow/release.yml"},
						{Key: "slsa.buildDefinition.externalParameters.workflow.ref", Value: "refs/heads/main"},
						{Key: "slsa.buildDefinition.externalParameters.workflow.repository", Value: "https://github.com/octocat/hello-world"},
						{Key: "slsa.buildDefinition.internalParameters.github.actor_id", Value: "1234567"},
						{Key: "slsa.buildDefinition.internalParameters.github.event_name", Value: "workflow_dispatch"},
						{Key: "slsa.buildDefinition.resolvedDependencies.0.digest.gitCommit", Value: "c27d339ee6075c1f744c5d4b200f7901aad2c369"},
						{Key: "slsa.buildDefinition.resolvedDependencies.0.uri", Value: "git+https://github.com/octocat/hello-world@refs/heads/main"},
						{Key: "slsa.buildDefinition.resolvedDependencies.1.uri", Value: "https://github.com/actions/virtual-environments/releases/tag/ubuntu20/20220515.1"},
						{Key: "slsa.runDetails.builder.id", Value: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v0.0.1"},
						{Key: "slsa.runDetails.metadata.invocationId", Value: "https://github.com/octocat/hello-world/actions/runs/1536140711/attempts/1"},
						{Key: "slsa.runDetails.metadata.startedOn", Value: "2023-01-01T12:34:56Z"},
					},
				},
			},
		},
	}

	slsa1time_2, _ = time.Parse(time.RFC3339, "2022-05-24T12:13:35.054695403Z")
	SlsaPreds1_2   = assembler.IngestPredicates{
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "npm",
					Namespace: ptrfrom.String("sigstore"),
					Name:      "segs",
					Version:   ptrfrom.String("1.2.0"),
					Subpath:   ptrfrom.String(""),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "sha1",
					Digest:    "5b8c0801d1f5d105351a403f58c38269de93f680",
				},
				IsOccurrence: &slsaIsOccurrence,
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "npm",
					Namespace: ptrfrom.String("sigstore"),
					Name:      "sigstore-js",
					Version:   ptrfrom.String("4.2.0"),
					Subpath:   ptrfrom.String(""),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "sha1",
					Digest:    "428601801d1f5d105351a403f58c38269de93f680",
				},
				IsOccurrence: &slsaIsOccurrence,
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "sha1",
					Digest:    "428601801d1f5d105351a403f58c38269de93f680",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "https://github.com/actions/runner",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "sha1",
					Digest:    "5b8c0801d1f5d105351a403f58c38269de93f680",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "https://github.com/npm/cli/gha/v2",
					SlsaVersion: "https://slsa.dev/provenance/v1",
					StartedOn:   &slsa1time_2,
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.buildDefinition.buildType", Value: "https://github.com/npm/cli/gha/v2"},
						{Key: "slsa.buildDefinition.resolvedDependencies.0.digest.sha1", Value: "5b8c0801d1f5d105351a403f58c38269de93f680"},
						{Key: "slsa.buildDefinition.resolvedDependencies.0.uri", Value: "pkg:npm/sigstore/segs@1.2.0"},
						{Key: "slsa.runDetails.builder.id", Value: "https://github.com/actions/runner"},
						{Key: "slsa.runDetails.metadata.invocationId", Value: "b6186090-c8ff-4f91-97cf-7a3b47699e57"},
						{Key: "slsa.runDetails.metadata.startedOn", Value: "2022-05-24T12:13:35.054695403Z"},
					},
				},
			},
		},
	}

	// TODO: needs to be resolved by https://github.com/guacsec/guac/issues/75
	Ident = []common.TrustInformation{}
	// Ident = assembler.IdentityNode{
	// 	ID:        "test",
	// 	Digest:    keyHash,
	// 	Key:       base64.StdEncoding.EncodeToString(pemBytes),
	// 	KeyType:   "ecdsa",
	// 	KeyScheme: "ecdsa",
	// 	NodeData: *assembler.NewObjectMetadata(
	// 		processor.SourceInformation{
	// 			Collector: "TestCollector",
	// 			Source:    "TestSource",
	// 		},
	// 	),
	// }

	DssePredicates = &assembler.IngestPredicates{}

	// SPDX Testdata

	topLevelPack, _       = asmhelpers.PurlToPkg("pkg:guac/spdx/gcr.io/google-containers/alpine-latest")
	baselayoutPack, _     = asmhelpers.PurlToPkg("pkg:alpine/alpine-baselayout@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2")
	keysPack, _           = asmhelpers.PurlToPkg("pkg:alpine/alpine-keys@2.4-r1?arch=x86_64&upstream=alpine-keys&distro=alpine-3.16.2")
	baselayoutdataPack, _ = asmhelpers.PurlToPkg("pkg:alpine/alpine-baselayout-data@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2")

	worldFilePack, _  = asmhelpers.PurlToPkg(asmhelpers.GuacFilePurl("sha256", "713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201", strP("/etc/apk/world")))
	worldFileArtifact = &model.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201",
	}

	rootFilePack, _  = asmhelpers.PurlToPkg(asmhelpers.GuacFilePurl("sha256", "575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3", strP("/etc/crontabs/root")))
	rootFileArtifact = &model.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3",
	}

	triggersFilePack, _  = asmhelpers.PurlToPkg(asmhelpers.GuacFilePurl("sha256", "5415cfe5f88c0af38df3b7141a3f9bc6b8178e9cf72d700658091b8f5539c7b4", strP("/lib/apk/db/triggers")))
	triggersFileArtifact = &model.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "5415cfe5f88c0af38df3b7141a3f9bc6b8178e9cf72d700658091b8f5539c7b4",
	}

	rsaPubFilePack, _  = asmhelpers.PurlToPkg(asmhelpers.GuacFilePurl("sha256", "9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97", strP("/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub")))
	rsaPubFileArtifact = &model.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97",
	}

	isOccurrenceJustifyTopPkg = &model.IsOccurrenceInputSpec{
		Justification: "cdx package with checksum",
	}

	isDepJustifyTopPkgJustification = "top-level package GUAC heuristic connecting to each file/package"

	isDepJustifyContainsJustification = "Derived from SPDX CONTAINS relationship"

	isDepJustifyContainedByJustification = "Derived from SPDX CONTAINED_BY relationship"

	isDepJustifyDependsOnJustification = "Derived from SPDX DEPENDS_ON relationship"

	isDepJustifyDependencyOfJustification = "Derived from SPDX DEPENDENCY_OF relationship"

	isCDXDepJustifyDependsJustification = "CDX BOM Dependency"

	isOccJustifyFile = &model.IsOccurrenceInputSpec{
		Justification: "spdx file with checksum",
	}

	SpdxDeps = []assembler.IsDependencyIngest{
		{
			Pkg:    topLevelPack,
			DepPkg: baselayoutPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    topLevelPack,
			DepPkg: baselayoutdataPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    topLevelPack,
			DepPkg: keysPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    topLevelPack,
			DepPkg: worldFilePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    topLevelPack,
			DepPkg: rootFilePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    topLevelPack,
			DepPkg: triggersFilePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    topLevelPack,
			DepPkg: rsaPubFilePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    baselayoutPack,
			DepPkg: keysPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyDependencyOfJustification,
			},
		},
		{
			Pkg:    rootFilePack,
			DepPkg: rsaPubFilePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyDependsOnJustification,
			},
		},
		{
			Pkg:    baselayoutPack,
			DepPkg: rootFilePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyContainsJustification,
			},
		},
		{
			Pkg:    keysPack,
			DepPkg: rsaPubFilePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyContainedByJustification,
			},
		},
	}

	SpdxOccurences = []assembler.IsOccurrenceIngest{
		{
			Pkg:          worldFilePack,
			Artifact:     worldFileArtifact,
			IsOccurrence: isOccJustifyFile,
		},
		{
			Pkg:          rootFilePack,
			Artifact:     rootFileArtifact,
			IsOccurrence: isOccJustifyFile,
		},
		{
			Pkg:          rsaPubFilePack,
			Artifact:     rsaPubFileArtifact,
			IsOccurrence: isOccJustifyFile,
		},
		{
			Pkg:          triggersFilePack,
			Artifact:     triggersFileArtifact,
			IsOccurrence: isOccJustifyFile,
		},
	}

	spdxTime, _ = time.Parse(time.RFC3339, "2022-09-24T17:27:55.556104Z")

	SpdxHasSBOM = []assembler.HasSBOMIngest{
		{
			Pkg: topLevelPack,
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:              "https://anchore.com/syft/image/alpine-latest-e78eca08-d9f4-49c7-97e0-6d4b9bfa99c2",
				Algorithm:        "sha256",
				Digest:           "8b5e8212cae084f92ff91f8625a50ea1070738cfc68ecca08bf04d64f64b9feb",
				DownloadLocation: "TestSource",
				KnownSince:       spdxTime,
			},
		},
	}

	SpdxCertifyLegal = []assembler.CertifyLegalIngest{
		{
			Pkg: baselayoutPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "GPL-2.0-only",
					ListVersion: ptrfrom.String("3.18"),
				},
			},
			Discovered: []model.LicenseInputSpec{
				{
					Name:        "GPL-2.0-only",
					ListVersion: ptrfrom.String("3.18"),
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense:   "GPL-2.0-only",
				DiscoveredLicense: "GPL-2.0-only",
				Justification:     "Found in SPDX document.",
				TimeScanned:       parseRfc3339("2022-09-24T17:27:55.556104Z"),
			},
		},
		{
			Pkg: baselayoutdataPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "GPL-2.0-only",
					ListVersion: ptrfrom.String("3.18"),
				},
			},
			Discovered: []model.LicenseInputSpec{
				{
					Name:        "GPL-2.0-only",
					ListVersion: ptrfrom.String("3.18"),
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense:   "GPL-2.0-only",
				DiscoveredLicense: "GPL-2.0-only",
				Justification:     "Found in SPDX document.",
				TimeScanned:       parseRfc3339("2022-09-24T17:27:55.556104Z"),
			},
		},
		{
			Pkg: keysPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "MIT",
					ListVersion: ptrfrom.String("3.18"),
				},
			},
			Discovered: []model.LicenseInputSpec{
				{
					Name:        "MIT",
					ListVersion: ptrfrom.String("3.18"),
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense:   "MIT",
				DiscoveredLicense: "MIT",
				Justification:     "Found in SPDX document.",
				TimeScanned:       parseRfc3339("2022-09-24T17:27:55.556104Z"),
			},
		},
	}

	SpdxHasMetadata = []assembler.HasMetadataIngest{
		{
			Pkg:          baselayoutPack,
			PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			HasMetadata: &model.HasMetadataInputSpec{
				Key:           "cpe",
				Value:         "cpe:2.3:a:alpine-baselayout:alpine-baselayout:3.2.0-r22:*:*:*:*:*:*:*",
				Justification: "spdx cpe external reference",
				Origin:        "GUAC SPDX",
				Collector:     "GUAC",
			},
		},
		{
			Pkg:          baselayoutPack,
			PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			HasMetadata: &model.HasMetadataInputSpec{
				Key:           "cpe",
				Value:         "cpe:2.3:a:alpine-baselayout:alpine_baselayout:3.2.0-r22:*:*:*:*:*:*:*",
				Justification: "spdx cpe external reference",
				Origin:        "GUAC SPDX",
				Collector:     "GUAC",
			},
		},
		{
			Pkg:          baselayoutdataPack,
			PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			HasMetadata: &model.HasMetadataInputSpec{
				Key:           "cpe",
				Value:         "cpe:2.3:a:alpine-baselayout-data:alpine-baselayout-data:3.2.0-r22:*:*:*:*:*:*:*",
				Justification: "spdx cpe external reference",
				Origin:        "GUAC SPDX",
				Collector:     "GUAC",
			},
		},
		{
			Pkg:          baselayoutdataPack,
			PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			HasMetadata: &model.HasMetadataInputSpec{
				Key:           "cpe",
				Value:         "cpe:2.3:a:alpine-baselayout-data:alpine_baselayout_data:3.2.0-r22:*:*:*:*:*:*:*",
				Justification: "spdx cpe external reference",
				Origin:        "GUAC SPDX",
				Collector:     "GUAC",
			},
		},
		{
			Pkg:          keysPack,
			PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			HasMetadata: &model.HasMetadataInputSpec{
				Key:           "cpe",
				Value:         "cpe:2.3:a:alpine-keys:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
				Justification: "spdx cpe external reference",
				Origin:        "GUAC SPDX",
				Collector:     "GUAC",
			},
		},
		{
			Pkg:          keysPack,
			PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			HasMetadata: &model.HasMetadataInputSpec{
				Key:           "cpe",
				Value:         "cpe:2.3:a:alpine-keys:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
				Justification: "spdx cpe external reference",
				Origin:        "GUAC SPDX",
				Collector:     "GUAC",
			},
		},
		{
			Pkg:          keysPack,
			PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			HasMetadata: &model.HasMetadataInputSpec{
				Key:           "cpe",
				Value:         "cpe:2.3:a:alpine:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
				Justification: "spdx cpe external reference",
				Origin:        "GUAC SPDX",
				Collector:     "GUAC",
			},
		},
		{
			Pkg:          keysPack,
			PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			HasMetadata: &model.HasMetadataInputSpec{
				Key:           "cpe",
				Value:         "cpe:2.3:a:alpine:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
				Justification: "spdx cpe external reference",
				Origin:        "GUAC SPDX",
				Collector:     "GUAC",
			},
		},
	}

	SpdxIngestionPredicates = assembler.IngestPredicates{
		IsDependency: SpdxDeps,
		IsOccurrence: SpdxOccurences,
		HasSBOM:      SpdxHasSBOM,
		HasMetadata:  SpdxHasMetadata,
		CertifyLegal: SpdxCertifyLegal,
	}

	// CycloneDX Testdata
	cdxTopLevelPack, _ = asmhelpers.PurlToPkg("pkg:guac/cdx/gcr.io/distroless/static@sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388?tag=nonroot")

	cdxTopLevelInvalidVersionPack, _ = asmhelpers.PurlToPkg("pkg:guac/cdx/gcr.io/distroless/static@nonroot")

	cdxTzdataPack, _ = asmhelpers.PurlToPkg("pkg:deb/debian/tzdata@2021a-1+deb11u6?arch=all&distro=debian-11")

	cdxNetbasePack, _ = asmhelpers.PurlToPkg("pkg:deb/debian/netbase@6.3?arch=all&distro=debian-11")

	cdxBasefilesPack, _ = asmhelpers.PurlToPkg("pkg:deb/debian/base-files@11.1+deb11u5?arch=amd64&distro=debian-11")

	cdxSmallRye, _ = asmhelpers.PurlToPkg("pkg:maven/io.smallrye.reactive/smallrye-mutiny-vertx-uri-template@2.27.0?type=jar")

	CdxDeps = []assembler.IsDependencyIngest{
		{
			Pkg:    cdxTopLevelPack,
			DepPkg: cdxBasefilesPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    cdxTopLevelPack,
			DepPkg: cdxNetbasePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    cdxTopLevelPack,
			DepPkg: cdxTzdataPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
	}

	cdxTime, _ = time.Parse(time.RFC3339, "2022-10-08T10:01:23-04:00")

	CdxHasSBOM = []assembler.HasSBOMIngest{
		{
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:              "urn:uuid:6a44e622-2983-4566-bf90-f87b6103ebaf",
				Algorithm:        "sha256",
				Digest:           "01942b5eefd3c15b50318c66d8d16627be573197c877e8a286a8cb12de7939cb",
				DownloadLocation: "TestSource",
				KnownSince:       cdxTime,
			},
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha256",
				Digest:    "6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388",
			},
		},
	}

	CdxIngestionPredicates = assembler.IngestPredicates{
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg: cdxTopLevelPack,
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "sha256",
					Digest:    "6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388",
				},
				IsOccurrence: isOccurrenceJustifyTopPkg,
			},
		},
		IsDependency: CdxDeps,
		HasSBOM:      CdxHasSBOM,
	}

	CdxHasSBOMInvalidVersion = []assembler.HasSBOMIngest{
		{
			Pkg: cdxTopLevelInvalidVersionPack,
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:              "urn:uuid:6a44e622-2983-4566-bf90-f87b6103ebaf",
				Algorithm:        "sha256",
				Digest:           "cb3ea440e0529e8b07e0e1b694e96ec10149fd00d8b634a0027e5e15f11e3c9b",
				DownloadLocation: "TestSource",
				KnownSince:       cdxTime,
			},
		},
	}

	CdxInvalidVersionDeps = []assembler.IsDependencyIngest{
		{
			Pkg:    cdxTopLevelInvalidVersionPack,
			DepPkg: cdxBasefilesPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    cdxTopLevelInvalidVersionPack,
			DepPkg: cdxNetbasePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    cdxTopLevelInvalidVersionPack,
			DepPkg: cdxTzdataPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
	}

	CdxIngestionInvalidVersionPredicates = assembler.IngestPredicates{
		IsDependency: CdxInvalidVersionDeps,
		HasSBOM:      CdxHasSBOMInvalidVersion,
	}

	cdxTopQuarkusPack, _ = asmhelpers.PurlToPkg("pkg:maven/org.acme/getting-started@1.0.0-SNAPSHOT?type=jar")

	cdxResteasyPack, _ = asmhelpers.PurlToPkg("pkg:maven/io.quarkus/quarkus-resteasy-reactive@2.13.4.Final?type=jar")

	cdxReactiveCommonPack, _ = asmhelpers.PurlToPkg("pkg:maven/io.quarkus/quarkus-resteasy-reactive-common@2.13.4.Final?type=jar")

	cdxMicroprofilePack, _ = asmhelpers.PurlToPkg("pkg:maven/org.eclipse.microprofile.context-propagation/microprofile-context-propagation-api@1.2?type=jar")

	cdxQuarkusDeps = []assembler.IsDependencyIngest{
		{
			Pkg:    cdxTopQuarkusPack,
			DepPkg: cdxResteasyPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeDirect,
				Justification:  isCDXDepJustifyDependsJustification,
			},
		},
		{
			Pkg:    cdxTopQuarkusPack,
			DepPkg: cdxReactiveCommonPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeIndirect,
				Justification:  isCDXDepJustifyDependsJustification,
			},
		},
		{
			Pkg:    cdxResteasyPack,
			DepPkg: cdxReactiveCommonPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeDirect,
				Justification:  isCDXDepJustifyDependsJustification,
			},
		},
	}
	lvUnknown       = "UNKNOWN"
	cdxQuarkusLegal = []assembler.CertifyLegalIngest{
		{
			Pkg: cdxResteasyPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxReactiveCommonPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
	}

	cdxQuarkusOccurrence = []assembler.IsOccurrenceIngest{
		{
			Pkg: cdxTopQuarkusPack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "85240ed8faa3cc4493db96d0223094842e7153890b091ff364040ad3ad89363157fc9d1bd852262124aec83134f0c19aa4fd0fa482031d38a76d74dfd36b7964",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
		{
			Pkg: cdxResteasyPack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "md5",
				Digest:    "bf39044af8c6ba66fc3beb034bc82ae8",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
		{
			Pkg: cdxResteasyPack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "615e56bdfeb591af8b5fdeadf019f8fa729643232d7e0768674411a7d959bb00e12e114280a6949f871514e1a86e01e0033372a0a826d15720050d7cffb80e69",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
		{
			Pkg: cdxReactiveCommonPack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "54ffa51cb2fb25e70871e4b69489814ebb3d23d4f958e83ef1f811c00a8753c6c30c5bbc1b48b6427357eb70e5c35c7b357f5252e246fbfa00b90ee22ad095e1",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
	}

	cdxQuarkusTime, _ = time.Parse(time.RFC3339, "2022-11-09T11:14:31Z")

	cdxQuarkusHasSBOM = []assembler.HasSBOMIngest{
		{
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "85240ed8faa3cc4493db96d0223094842e7153890b091ff364040ad3ad89363157fc9d1bd852262124aec83134f0c19aa4fd0fa482031d38a76d74dfd36b7964",
			},
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:              "urn:uuid:0697952e-9848-4785-95bf-f81ff9731682",
				Algorithm:        "sha256",
				Digest:           "036a9f51468f5ce6eec7c310583164ed0ab9f58d7c03380a3fe19d420609e3de",
				DownloadLocation: "TestSource",
				KnownSince:       cdxQuarkusTime,
			},
		},
	}

	CdxQuarkusIngestionPredicates = assembler.IngestPredicates{
		IsDependency: cdxQuarkusDeps,
		IsOccurrence: cdxQuarkusOccurrence,
		HasSBOM:      cdxQuarkusHasSBOM,
		CertifyLegal: cdxQuarkusLegal,
	}

	cdxLegalDeps = []assembler.IsDependencyIngest{
		{
			Pkg:    cdxTopQuarkusPack,
			DepPkg: cdxResteasyPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeDirect,
				Justification:  isCDXDepJustifyDependsJustification,
			},
		},
		{
			Pkg:    cdxTopQuarkusPack,
			DepPkg: cdxReactiveCommonPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeIndirect,
				Justification:  isCDXDepJustifyDependsJustification,
			},
		},
		{
			Pkg:    cdxResteasyPack,
			DepPkg: cdxReactiveCommonPack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeDirect,
				Justification:  isCDXDepJustifyDependsJustification,
			},
		},
		{
			Pkg:    cdxTopQuarkusPack,
			DepPkg: cdxSmallRye,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    cdxTopQuarkusPack,
			DepPkg: cdxNetbasePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    cdxTopQuarkusPack,
			DepPkg: cdxMicroprofilePack,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
	}
	customLincenseText   = "This is the text of the custom license I wrote"
	cdxLegalCertifyLegal = []assembler.CertifyLegalIngest{
		{
			Pkg: cdxNetbasePack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
				{
					Name:   "LicenseRef-a7fb6b15",
					Inline: &customLincenseText,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0 AND LicenseRef-a7fb6b15",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxResteasyPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxReactiveCommonPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
				{
					Name:   "LicenseRef-a7fb6b15",
					Inline: &customLincenseText,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0 AND LicenseRef-a7fb6b15",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxSmallRye,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
				{
					Name:        "MIT",
					ListVersion: &lvUnknown,
				},
				{
					Name:        "GPL-2.0-only",
					ListVersion: &lvUnknown,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0 AND (MIT OR GPL-2.0-only)",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxTopQuarkusPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "GPL-2.0",
					ListVersion: &lvUnknown,
				},
				{
					Name:        "LGPL-3.0-or-later",
					ListVersion: &lvUnknown,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "GPL-2.0 AND LGPL-3.0-or-later",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxMicroprofilePack,
			Declared: []model.LicenseInputSpec{
				{
					Name:   "LicenseRef-a7fb6b15",
					Inline: &customLincenseText,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "LicenseRef-a7fb6b15",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
	}

	cdxLegalOccurrence = []assembler.IsOccurrenceIngest{
		{
			Pkg: cdxTopQuarkusPack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "85240ed8faa3cc4493db96d0223094842e7153890b091ff364040ad3ad89363157fc9d1bd852262124aec83134f0c19aa4fd0fa482031d38a76d74dfd36b7964",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
		{
			Pkg: cdxResteasyPack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "md5",
				Digest:    "bf39044af8c6ba66fc3beb034bc82ae8",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
		{
			Pkg: cdxResteasyPack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "615e56bdfeb591af8b5fdeadf019f8fa729643232d7e0768674411a7d959bb00e12e114280a6949f871514e1a86e01e0033372a0a826d15720050d7cffb80e69",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
		{
			Pkg: cdxReactiveCommonPack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "54ffa51cb2fb25e70871e4b69489814ebb3d23d4f958e83ef1f811c00a8753c6c30c5bbc1b48b6427357eb70e5c35c7b357f5252e246fbfa00b90ee22ad095e1",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
		{
			Pkg: cdxSmallRye,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "md5",
				Digest:    "8756663af131035a2090d83f5f1b4054",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
		{
			Pkg: cdxNetbasePack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "87gna51cb2fb25e70871e4b69489814ebb3d23d4f958e83ef1f811c00a8753c6c30c5bbc1b48b6427357eb70e5c35c7b357f5252e246fbfa00b90ee22ad095e1",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
		{
			Pkg: cdxMicroprofilePack,
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha-256",
				Digest:    "1576e21f3bf9cc3a3092e7cd40e9c9fef70532223af98a9218c1c9c885a71251",
			},
			IsOccurrence: isOccurrenceJustifyTopPkg,
		},
	}

	cdxLegalHasSBOM = []assembler.HasSBOMIngest{
		{
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "85240ed8faa3cc4493db96d0223094842e7153890b091ff364040ad3ad89363157fc9d1bd852262124aec83134f0c19aa4fd0fa482031d38a76d74dfd36b7964",
			},
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:              "urn:uuid:0697952e-9848-4785-95bf-f81ff9731682",
				Algorithm:        "sha256",
				Digest:           "b9691aeacfe8adca01097f2e2af3484038df6e367524f9c38f6e1696f8971ed9",
				DownloadLocation: "",
				KnownSince:       cdxQuarkusTime,
			},
		},
	}

	cdxLegalHasSBOMNoInLine = []assembler.HasSBOMIngest{
		{
			Artifact: &model.ArtifactInputSpec{
				Algorithm: "sha3-512",
				Digest:    "85240ed8faa3cc4493db96d0223094842e7153890b091ff364040ad3ad89363157fc9d1bd852262124aec83134f0c19aa4fd0fa482031d38a76d74dfd36b7964",
			},
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:              "urn:uuid:0697952e-9848-4785-95bf-f81ff9731682",
				Algorithm:        "sha256",
				Digest:           "09522e1c53eb2b919446c2e904f6517482de731dc6e61d7e7ad559675cb9355b",
				DownloadLocation: "",
				KnownSince:       cdxQuarkusTime,
			},
		},
	}

	CdxQuarkusLegalPredicates = assembler.IngestPredicates{
		IsDependency: cdxLegalDeps,
		IsOccurrence: cdxLegalOccurrence,
		HasSBOM:      cdxLegalHasSBOM,
		CertifyLegal: cdxLegalCertifyLegal,
	}

	CdxQuarkusLegalNoInlinePredicates = assembler.IngestPredicates{
		IsDependency: cdxLegalDeps,
		IsOccurrence: cdxLegalOccurrence,
		HasSBOM:      cdxLegalHasSBOMNoInLine,
		CertifyLegal: cdxLegalCertifyLegalNoInline,
	}

	cdxLegalCertifyLegalNoInline = []assembler.CertifyLegalIngest{
		{
			Pkg: cdxNetbasePack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
				{
					Name:   "LicenseRef-a7fb6b15",
					Inline: &customLincenseText,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0 AND LicenseRef-a7fb6b15",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxResteasyPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxReactiveCommonPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
				{
					Name:   "LicenseRef-a7fb6b15",
					Inline: &customLincenseText,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0 AND LicenseRef-a7fb6b15 AND LicenseRef-59a01e67",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxSmallRye,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
				{
					Name:        "MIT",
					ListVersion: &lvUnknown,
				},
				{
					Name:        "GPL-2.0-only",
					ListVersion: &lvUnknown,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0 AND (MIT OR GPL-2.0-only)",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxTopQuarkusPack,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "GPL-2.0",
					ListVersion: &lvUnknown,
				},
				{
					Name:        "LGPL-3.0-or-later",
					ListVersion: &lvUnknown,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "GPL-2.0 AND LGPL-3.0-or-later",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
		{
			Pkg: cdxMicroprofilePack,
			Declared: []model.LicenseInputSpec{
				{
					Name:   "LicenseRef-a7fb6b15",
					Inline: &customLincenseText,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "LicenseRef-a7fb6b15 AND LicenseRef-59a01e67",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     cdxQuarkusTime,
			},
		},
	}

	cdxWebAppPackage, _ = asmhelpers.PurlToPkg("pkg:npm/web-app@1.0.0")

	cdxBootstrapPackage, _ = asmhelpers.PurlToPkg("pkg:npm/bootstrap@4.0.0-beta.2")

	CdxNpmDeps = []assembler.IsDependencyIngest{
		{
			Pkg:    cdxWebAppPackage,
			DepPkg: cdxBootstrapPackage,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
	}

	cdxNpmTime, _ = time.Parse(time.RFC3339, "2022-11-22T17:14:57Z")

	CdxNpmHasSBOM = []assembler.HasSBOMIngest{
		{
			Pkg: cdxWebAppPackage,
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:              "",
				Algorithm:        "sha256",
				Digest:           "35363f03c80f26a88db6f2400771bdcc6624bb7b61b96da8503be0f757605fde",
				DownloadLocation: "TestSource",
				KnownSince:       cdxNpmTime,
			},
		},
	}

	CdxNpmIngestionPredicates = assembler.IngestPredicates{
		IsDependency: CdxNpmDeps,
		HasSBOM:      CdxNpmHasSBOM,
	}

	quarkusParentPackage, _ = asmhelpers.PurlToPkg("pkg:maven/io.quarkus/quarkus-parent@999-SNAPSHOT?type=pom")
	quarkusTime, _          = time.Parse(time.RFC3339, "2023-02-16T21:52:02Z")

	quarkusParentPackageHasSBOM = []assembler.HasSBOMIngest{
		{
			Pkg: quarkusParentPackage,
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:              "urn:uuid:8a689387-e9b4-4ba2-835c-a2c3dde6181d",
				Algorithm:        "sha256",
				Digest:           "fcd4d1f9c83c274fbc2dabdca4e7de749b23fab1aa15dc2854880a13479fa74e",
				DownloadLocation: "TestSource",
				KnownSince:       quarkusTime,
			},
		},
	}

	quarkusParentPackageLegal = []assembler.CertifyLegalIngest{
		{
			Pkg: quarkusParentPackage,
			Declared: []model.LicenseInputSpec{
				{
					Name:        "Apache-2.0",
					ListVersion: &lvUnknown,
				},
			},
			CertifyLegal: &model.CertifyLegalInputSpec{
				DeclaredLicense: "Apache-2.0",
				Justification:   "Found in CycloneDX document",
				TimeScanned:     quarkusTime,
			},
		},
	}

	CdxEmptyIngestionPredicates = assembler.IngestPredicates{
		HasSBOM:      quarkusParentPackageHasSBOM,
		CertifyLegal: quarkusParentPackageLegal,
	}

	NestedComponentsPredicates = assembler.IngestPredicates{
		IsDependency: ociComponentsIsDependencyIngests,
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg:          ociMandrel,
				Artifact:     ociMandrelArtifact,
				IsOccurrence: isOccurrenceJustifyTopPkg,
			},
		},
		HasSBOM: nestedComponentsHasSBOM,
	}

	FlatComponentsPredicates = assembler.IngestPredicates{
		IsDependency: ociComponentsIsDependencyIngests,
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg:          ociMandrel,
				Artifact:     ociMandrelArtifact,
				IsOccurrence: isOccurrenceJustifyTopPkg,
			},
		},
		HasSBOM: flatComponentsHasSBOM,
	}

	XRayComponentsTime, _ = time.Parse(time.RFC3339, "2024-12-11T10:06:41+00:00")

	XraySBOMVulnsPredicates = assembler.IngestPredicates{
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "guac",
					Namespace: ptrfrom.String("cdx/library"),
					Name:      "maven",
					Version:   ptrfrom.String("sha256__09c4bf58d7e7e31bdc1ab73ef10349b3a47c9a814e715e409034fb3293253ce2"),
					Subpath:   ptrfrom.String(""),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String(""),
					Name:      "debian:buster:apt",
					Version:   ptrfrom.String("1.8.2.2"),
					Subpath:   ptrfrom.String(""),
				},
				IsDependency: &model.IsDependencyInputSpec{
					DependencyType: model.DependencyTypeUnknown,
					Justification:  isDepJustifyTopPkgJustification,
				},
			},
		},
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String(""),
					Name:      "debian:buster:apt",
					Version:   ptrfrom.String("1.8.2.2"),
					Subpath:   ptrfrom.String(""),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "sha-256",
					Digest:    "db5c8bd205d41e520f615251ae97c9610a0fb312841428a7a25072831f6bee83",
				},
				IsOccurrence: isOccurrenceJustifyTopPkg,
			},
		},
		HasSBOM: []assembler.HasSBOMIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "guac",
					Namespace: ptrfrom.String("cdx/library"),
					Name:      "maven",
					Version:   ptrfrom.String("sha256__09c4bf58d7e7e31bdc1ab73ef10349b3a47c9a814e715e409034fb3293253ce2"),
					Subpath:   ptrfrom.String(""),
				},
				HasSBOM: &model.HasSBOMInputSpec{
					Uri:        "urn:uuid:e8300d83-d8d8-4e91-63e7-3d95b8900f45",
					Algorithm:  "sha256",
					Digest:     "5b43f9ae2939c3ce859a1beda091d699d05853f76ed2843e021c24e266dbbc4d",
					KnownSince: XRayComponentsTime,
				},
			},
		},
		CertifyVuln: []assembler.CertifyVulnIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String(""),
					Name:      "debian:buster:apt",
					Version:   ptrfrom.String("1.8.2.2"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "cve-2011-3374",
				},
				VulnData: &model.ScanMetadataInput{
					TimeScanned: time.Unix(0, 0).UTC(),
				},
			},
		},
		Vex: []assembler.VexIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String(""),
					Name:      "debian:buster:apt",
					Version:   ptrfrom.String("1.8.2.2"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "cve-2011-3374",
				},
				VexData: &model.VexStatementInputSpec{
					Status:           model.VexStatusUnderInvestigation,
					VexJustification: model.VexJustificationNotProvided,
					StatusNotes:      "There are no applicability scanners for this specific CVE\n##### Deployment mitigations\n\nClient-side mitigation: In case a repository is cloned/pulled with no intention of pushing anything, the `git sparse-checkout` feature can be enabled to avoid pulling the `.gitattributes` file. It can be performed as follows:\r\n```\r\ngit clone \u003cREPOSITORY URL\u003e --no-checkout\r\ncd \u003cREPOSITORY NAME\u003e\r\ngit sparse-checkout init\r\ngit sparse-checkout set --no-cone '/*' '!.gitattributes'\r\ngit checkout\r\n```\n\n##### Deployment mitigations\n\nAlthough the issue resides on the Git client's side, Git servers can also avoid infection by malicious actors from their side as well. Here is a git hook that will run after each push to check the size of the `.gitattributes` file can prevent from this vulnerability. The hook should be in the `/path/to/repository.git/hooks/` folder under the name of `pre-receive`:\r\n```\r\n#!/bin/sh\r\n# pre-receive hook to prevent oversized .gitattributes files from being pushed\r\n\r\n# 1GB of maximum allowed size for .gitattributes file (in bytes)\r\nmax_size=1048576\r\n\r\n# check each pushed file\r\nwhile read oldrev newrev refname; do\r\n    # check for .gitattributes file\r\n    if [ \"$(git rev-parse --verify $newrev:.gitattributes 2\u003e /dev/null)\" != \"\" ]; then\r\n        # check file size\r\n        size=$(git cat-file -s $newrev:.gitattributes)\r\n        if [ $size -gt $max_size ]; then\r\n            echo \"Error: .gitattributes file exceeds maximum allowed size of $max_size bytes.\"\r\n            exit 1\r\n        fi\r\n    fi\r\ndone\r\n\r\nexit 0\r\n```",
					KnownSince:       time.Unix(0, 0).UTC(),
				},
			},
		},
		CertifyLegal: []assembler.CertifyLegalIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String(""),
					Name:      "debian:buster:apt",
					Version:   ptrfrom.String("1.8.2.2"),
					Subpath:   ptrfrom.String(""),
				},
				Declared: []model.LicenseInputSpec{
					{
						Name:        "GPL-2.0-only",
						ListVersion: ptrfrom.String("UNKNOWN"),
					},
				},
				CertifyLegal: &model.CertifyLegalInputSpec{
					DeclaredLicense: "GPL-2.0-only",
					Justification:   "Found in CycloneDX document",
					TimeScanned:     XRayComponentsTime,
				},
			},
		},
	}

	ociComponentsIsDependencyIngests = []assembler.IsDependencyIngest{
		{
			Pkg:    ociMandrel,
			DepPkg: mavenCompiler,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeDirect,
				Justification:  isCDXDepJustifyDependsJustification,
			},
		},
		{
			Pkg:    ociMandrel,
			DepPkg: mavenCompiler,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    ociMandrel,
			DepPkg: mavenCompiler,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    ociMandrel,
			DepPkg: ociMandrel,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    ociMandrel,
			DepPkg: abattisCantarellFonts,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeDirect,
				Justification:  isCDXDepJustifyDependsJustification,
			},
		},
		{
			Pkg:    ociMandrel,
			DepPkg: abattisCantarellFonts,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
		{
			Pkg:    ociMandrel,
			DepPkg: abattisCantarellFonts,
			IsDependency: &model.IsDependencyInputSpec{
				DependencyType: model.DependencyTypeUnknown,
				Justification:  isDepJustifyTopPkgJustification,
			},
		},
	}

	ociMandrel, _            = asmhelpers.PurlToPkg("pkg:oci/mandrel-for-jdk-21-rhel8@sha256%3A41d92dafa5ccbf7f76fa81c5a0e7de83c51166f27bea9b98df018f644016bf04?arch=amd64&os=linux&tag=23.1-13.1724180416")
	mavenCompiler, _         = asmhelpers.PurlToPkg("pkg:maven/compiler/compiler@23.1.4.0-1-redhat-00001?type=jar")
	abattisCantarellFonts, _ = asmhelpers.PurlToPkg("pkg:rpm/redhat/abattis-cantarell-fonts@0.0.25-6.el8?arch=noarch")
	ociMandrelArtifact       = &model.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "41d92dafa5ccbf7f76fa81c5a0e7de83c51166f27bea9b98df018f644016bf04",
	}

	nestedComponentsHasSBOM = []assembler.HasSBOMIngest{
		{
			Artifact: ociMandrelArtifact,
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:        "urn:uuid:c096003c-c9fa-4d9e-9390-fefa51745fe1",
				Algorithm:  "sha256",
				Digest:     "6a9598f69e87d0c45f3dd4c5d69d8812b734b28f07506a9f7b6ada7e9696c5e5",
				KnownSince: nestedComponentsTime,
			},
		},
	}

	flatComponentsHasSBOM = []assembler.HasSBOMIngest{
		{
			Artifact: ociMandrelArtifact,
			HasSBOM: &model.HasSBOMInputSpec{
				Uri:        "urn:uuid:c096003c-c9fa-4d9e-9390-fefa51745fe1",
				Algorithm:  "sha256",
				Digest:     "1dedfbd09dbf68a29279395444e76f300285cf1731ad25f39252c4d689403531",
				KnownSince: nestedComponentsTime,
			},
		},
	}

	nestedComponentsTime, _ = time.Parse(time.RFC3339, "2024-09-24T08:20:03Z")

	// ceritifer testdata

	Text4ShellVulAttestation = `{
		"type":"https://in-toto.io/Statement/v1",
		"subject":[
		   {
			  "uri":"pkg:maven/org.apache.commons/commons-text@1.9"
		   }
		],
		"predicate_type":"https://in-toto.io/attestation/vulns/v0.1",
		"predicate":{
		   "scanner":{
			  "uri":"osv.dev",
			  "version":"0.0.14",
			  "db":{
			  },
			  "result":[
				 {
					"id":"GHSA-599f-7c49-w659"
				 }
			  ]
		   },
		   "metadata":{
			  "scanStartedOn":"2022-11-22T13:19:18.825699-05:00",
                          "scanFinishedOn":"2022-11-22T13:19:18.825699-05:00"
		   }
		}
	 }`
	SecondLevelVulAttestation = `{
		"type":"https://in-toto.io/Statement/v1",
		"subject":[
		   {
			  "uri":"pkg:oci/vul-secondLevel-latest?repository_url=gcr.io"
		   }
		],
		"predicate_type":"https://in-toto.io/attestation/vulns/v0.1",
		"predicate":{
		   "scanner": {
			"uri": "osv.dev",
			"version": "0.0.14"
		   },
		   "metadata":{
			  "scanStartedOn":"2022-11-22T13:19:18.825699-05:00",
			  "scanFinishedOn":"2022-11-22T13:19:18.825699-05:00"
		   }
		}
	 }`
	RootVulAttestation = `{
		"type":"https://in-toto.io/Statement/v1",
		"subject":[
		   {
			  "uri":"pkg:oci/vul-image-latest?repository_url=gcr.io"
		   }
		],
		"predicate_type":"https://in-toto.io/attestation/vulns/v0.1",
		"predicate":{
		   "scanner": {
			"uri": "osv.dev",
			"version": "0.0.14"
		   },
		   "metadata":{
			  "scanStartedOn":"2022-11-22T13:19:18.825699-05:00",
			  "scanFinishedOn":"2022-11-22T13:19:18.825699-05:00"
		   }
		}
	 }`
	Log4JVulAttestation = `{
		"type":"https://in-toto.io/Statement/v1",
		"subject":[
		   {
			  "uri":"pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1"
		   }
		],
		"predicate_type":"https://in-toto.io/attestation/vulns/v0.1",
		"predicate":{
		   "scanner":{
			  "uri":"osv.dev",
			  "version":"0.0.14",
			  "db":{
			  },
			  "result":[
				 {
					"id":"GHSA-7rjr-3q55-vv33"
				 },
				 {
					"id":"GHSA-8489-44mv-ggj8"
				 },
				 {
					"id":"GHSA-fxph-q3j8-mv87"
				 },
				 {
					"id":"GHSA-jfh8-c2jp-5v3q"
				 },
				 {
					"id":"GHSA-p6xc-xr62-6r2g"
				 },
				 {
					"id":"GHSA-vwqq-5vrc-xw9h"
				 }
			  ]
		   },
		   "metadata":{
			  "scanStartedOn":"2022-11-22T13:19:18.825699-05:00",
			  "scanFinishedOn":"2022-11-22T13:19:18.825699-05:00"
		   }
		}
	 }`

	RootPackage = root_package.PackageNode{
		Purl: "pkg:oci/vul-image-latest?repository_url=gcr.io",
	}

	SecondLevelPackage = root_package.PackageNode{
		Purl: "pkg:oci/vul-secondLevel-latest?repository_url=gcr.io",
	}

	Log4JPackage = root_package.PackageNode{
		Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1",
	}

	Text4ShellPackage = root_package.PackageNode{
		Purl: "pkg:maven/org.apache.commons/commons-text@1.9",
	}

	//go:embed exampledata/cd-mock/cd-maven-apachecommons-text4shell.json
	CDApacheCommonsText4ShellResponse []byte

	//go:embed exampledata/cd-mock/cd-maven-commons-text4shell.json
	CDMavenCommonsText4ShellResponse []byte

	//go:embed exampledata/cd-mock/cd-maven-log4j.json
	CDMavenLog4JResponse []byte

	//go:embed exampledata/cd-mock/cd-sourcearchive-log4j.json
	CDSourceArchiveLog4JResponse []byte

	//go:embed exampledata/cd-mock/cd-sourcearchive-text4shell.json
	CDSourceArchiveText4ShellResponse []byte

	//go:embed exampledata/cd-mock/cd-maven-iovertx.json
	CDMavenIOVertxResponse []byte

	VertxWebCommonAttestation = `{
		"type": "https://in-toto.io/Statement/v1",
		"subject": [
			{
				"uri": "pkg:maven/io.vertx/vertx-web-common@4.3.7?type=jar"
			}
		],
		"predicate_type": "https://in-toto.io/attestation/vulns/v0.1",
		"predicate": {
			"scanner": {
				"uri": "osv.dev",
				"version": "0.0.14"
			},
			"metadata": {
				"scanStartedOn":"2022-11-22T13:19:18.825699-05:00",
				"scanFinishedOn":"2022-11-22T13:19:18.825699-05:00"
			}
		}
	}`

	VertxAuthCommonAttestation = `{
		"type": "https://in-toto.io/Statement/v1",
		"subject": [
			{
				"uri": "pkg:maven/io.vertx/vertx-auth-common@4.3.7?type=jar"
			}
		],
		"predicate_type": "https://in-toto.io/attestation/vulns/v0.1",
		"predicate": {
			"scanner": {
				"uri": "osv.dev",
				"version": "0.0.14"
			},
			"metadata": {
				"scanStartedOn":"2022-11-22T13:19:18.825699-05:00",
				"scanFinishedOn":"2022-11-22T13:19:18.825699-05:00"
			}
		}
	}`

	VertxBridgeCommonAttestation = `{
		"type": "https://in-toto.io/Statement/v1",
		"subject": [
			{
				"uri": "pkg:maven/io.vertx/vertx-bridge-common@4.3.7?type=jar"
			}
		],
		"predicate_type": "https://in-toto.io/attestation/vulns/v0.1",
		"predicate": {
			"scanner": {
				"uri": "osv.dev",
				"version": "0.0.14"
			},
			"metadata": {
				"scanStartedOn":"2022-11-22T13:19:18.825699-05:00",
				"scanFinishedOn":"2022-11-22T13:19:18.825699-05:00"
			}
		}
	}`

	VertxCoreCommonAttestation = `{
		"type": "https://in-toto.io/Statement/v1",
		"subject": [
			{
				"uri": "pkg:maven/io.vertx/vertx-core@4.3.7?type=jar"
			}
		],
		"predicate_type": "https://in-toto.io/attestation/vulns/v0.1",
		"predicate": {
			"scanner": {
				"uri": "osv.dev",
				"version": "0.0.14",
				"result": [
					{
						"id": "GHSA-9ph3-v2vh-3qx7"
					}
				]
			},
			"metadata": {
				"scanStartedOn":"2023-02-15T11:10:08.986506-08:00",
				"scanFinishedOn":"2023-02-15T11:10:08.986506-08:00"
			}
		}
	}`

	VertxWebAttestation = `{
		"type": "https://in-toto.io/Statement/v1",
		"subject": [
			{
				"uri": "pkg:maven/io.vertx/vertx-web@4.3.7?type=jar"
			}
		],
		"predicate_type": "https://in-toto.io/attestation/vulns/v0.1",
		"predicate": {
			"scanner": {
				"uri": "osv.dev",
				"version": "0.0.14",
				"result": [
					{
						"id": "GHSA-53jx-vvf9-4x38"
					}
				]
			},
			"metadata": {
				"scanStartedOn":"2023-02-15T11:10:08.986506-08:00",
				"scanFinishedOn":"2023-02-15T11:10:08.986506-08:00"
			}
		}
	}`

	VertxWebCommonPackage = root_package.PackageNode{
		Purl: "pkg:maven/io.vertx/vertx-web-common@4.3.7?type=jar",
	}

	VertxAuthCommonPackage = root_package.PackageNode{
		Purl: "pkg:maven/io.vertx/vertx-auth-common@4.3.7?type=jar",
	}

	VertxBridgeCommonPackage = root_package.PackageNode{
		Purl: "pkg:maven/io.vertx/vertx-bridge-common@4.3.7?type=jar",
	}

	VertxCoreCommonPackage = root_package.PackageNode{
		Purl: "pkg:maven/io.vertx/vertx-core@4.3.7?type=jar",
	}

	VertxWebPackage = root_package.PackageNode{
		Purl: "pkg:maven/io.vertx/vertx-web@4.3.7?type=jar",
	}

	// Deps.dev

	CollectedPypiWheelAxle = `{
   "CurrentPackage":{
      "name":"wheel-axle-runtime",
      "namespace":"",
      "qualifiers":null,
      "subpath":"",
      "type":"pypi",
      "version":"0.0.4"
   },
   "DepPackages":[
      {
         "CurrentPackage":{
            "name":"filelock",
            "namespace":"",
            "qualifiers":null,
            "subpath":"",
            "type":"pypi",
            "version":null
         },
         "DepPackages":null,
         "IsDepPackages":null,
         "Scorecard":null,
         "Source":{
            "commit":null,
            "name":"py-filelock",
            "namespace":"github.com/tox-dev",
            "tag":null,
            "type":"git"
         },
         "UpdateTime":"2022-11-21T17:45:50.52Z"
      }
   ],
   "IsDepPackages":[
      {
         "CurrentPackageInput":{
            "name":"wheel-axle-runtime",
            "namespace":"",
            "qualifiers":null,
            "subpath":"",
            "type":"pypi",
            "version":null
         },
         "DepPackageInput":{
            "name":"filelock",
            "namespace":"",
            "qualifiers":null,
            "subpath":"",
            "type":"pypi",
            "version":null
         },
         "IsDependency":{
            "collector":"",
            "dependencyType":"DIRECT",
            "justification":"dependency data collected via deps.dev",
            "origin":""
         }
      }
   ],
   "Scorecard":null,
   "Source":{
      "commit":null,
      "name":"wheel-axle-runtime",
      "namespace":"github.com/karellen",
      "tag":null,
      "type":"git"
   },
   "UpdateTime":"2022-11-21T17:45:50.52Z"
}`

	CollectedMavenWebJars = `{
		"CurrentPackage":{
		   "name":"a",
		   "namespace":"org.webjars.npm",
		   "qualifiers":null,
		   "subpath":"",
		   "type":"maven",
		   "version":"2.1.2"
		},
		"DepPackages":null,
		"IsDepPackages":null,
		"Scorecard":{
		   "aggregateScore":5,
		   "checks":[
			  {
				 "check":"Maintained",
				 "score":0
			  },
			  {
				 "check":"CII-Best-Practices",
				 "score":0
			  },
			  {
				 "check":"License",
				 "score":0
			  },
			  {
				 "check":"Signed-Releases",
				 "score":-1
			  },
			  {
				 "check":"Binary-Artifacts",
				 "score":10
			  },
			  {
				 "check":"Token-Permissions",
				 "score":10
			  },
			  {
				 "check":"Packaging",
				 "score":-1
			  },
			  {
				 "check":"Dangerous-Workflow",
				 "score":10
			  },
			  {
				 "check":"Branch-Protection",
				 "score":0
			  },
			  {
				 "check":"Pinned-Dependencies",
				 "score":10
			  },
			  {
				 "check":"Fuzzing",
				 "score":0
			  },
			  {
				 "check":"Security-Policy",
				 "score":0
			  },
			  {
				 "check":"Vulnerabilities",
				 "score":10
			  }
		   ],
		   "collector":"",
		   "origin":"",
		   "scorecardCommit":"1c441f3773712e6d12de6b353c25b4c093c11015",
		   "scorecardVersion":"v4.10.5-58-g1c441f3",
		   "timeScanned":"2022-11-21T17:45:50.52Z"
		},
		"Source":{
		   "commit":null,
		   "name":"a",
		   "namespace":"github.com/alfateam",
		   "tag":null,
		   "type":"git"
		},
		"UpdateTime":"2022-11-21T17:45:50.52Z"
	 }`

	CollectedNPMReact = `{
		"CurrentPackage":{
		   "name":"react",
		   "namespace":"",
		   "qualifiers":null,
		   "subpath":"",
		   "type":"npm",
		   "version":"17.0.0"
		},
		"DepPackages":[
		   {
			  "CurrentPackage":{
				 "name":"js-tokens",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"4.0.0"
			  },
			  "DepPackages":null,
			  "IsDepPackages":null,
			  "Scorecard":null,
			  "Source":{
				 "commit":null,
				 "name":"js-tokens",
				 "namespace":"github.com/lydell",
				 "tag":null,
				 "type":"git"
			  },
			  "UpdateTime":"2022-11-21T17:45:50.52Z"
		   },
		   {
			  "CurrentPackage":{
				 "name":"loose-envify",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"1.4.0"
			  },
			  "DepPackages":null,
			  "IsDepPackages":null,
			  "Scorecard":null,
			  "Source":null,
			  "UpdateTime":"2022-11-21T17:45:50.52Z"
		   },
		   {
			  "CurrentPackage":{
				 "name":"object-assign",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"4.1.1"
			  },
			  "DepPackages":null,
			  "IsDepPackages":null,
			  "Scorecard":null,
			  "Source":{
				 "commit":null,
				 "name":"object-assign",
				 "namespace":"github.com/sindresorhus",
				 "tag":null,
				 "type":"git"
			  },
			  "UpdateTime":"2022-11-21T17:45:50.52Z"
		   }
		],
		"IsDepPackages":[
		   {
			  "CurrentPackageInput":{
				 "name":"react",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"17.0.0"
			  },
			  "DepPackageInput":{
				 "name":"loose-envify",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"1.4.0"
			  },
			  "IsDependency":{
				 "collector":"",
				 "dependencyType":"DIRECT",
				 "justification":"dependency data collected via deps.dev",
				 "origin":""
			  }
		   },
		   {
			  "CurrentPackageInput":{
				 "name":"react",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"17.0.0"
			  },
			  "DepPackageInput":{
				 "name":"object-assign",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"4.1.1"
			  },
			  "IsDependency":{
				 "collector":"",
				 "dependencyType":"DIRECT",
				 "justification":"dependency data collected via deps.dev",
				 "origin":""
			  }
		   },
		   {
			  "CurrentPackageInput":{
				 "name":"loose-envify",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"1.4.0"
			  },
			  "DepPackageInput":{
				 "name":"js-tokens",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"4.0.0"
			  },
			  "IsDependency":{
				 "collector":"",
				 "dependencyType":"DIRECT",
				 "justification":"dependency data collected via deps.dev",
				 "origin":""
			  }
		   }
		],
		"Scorecard":null,
		"Source":{
		   "commit":null,
		   "name":"react",
		   "namespace":"github.com/facebook",
		   "tag":null,
		   "type":"git"
		},
		"UpdateTime":"2022-11-21T17:45:50.52Z"
	 }`

	CollectedGoLangSpdxToolsGolang = `{
	"CurrentPackage": {
		"type": "golang",
		"namespace": "github.com/spdx",
		"name": "tools-golang",
		"version": "v0.1.0",
		"qualifiers": null,
		"subpath": ""
	},
	"Source": {
		"type": "git",
		"namespace": "github.com/spdx",
		"name": "tools-golang",
		"tag": null,
		"commit": null
	},
	"Scorecard": {
		"checks": [
		{
			"check": "Dangerous-Workflow",
			"score": 10
		},
		{
			"check": "Security-Policy",
			"score": 3
		},
		{
			"check": "Packaging",
			"score": -1
		},
		{
			"check": "Maintained",
			"score": 0
		},
		{
			"check": "Token-Permissions",
			"score": 0
		},
		{
			"check": "Code-Review",
			"score": 7
		},
		{
			"check": "Binary-Artifacts",
			"score": 10
		},
		{
			"check": "Pinned-Dependencies",
			"score": 0
		},
		{
			"check": "CII-Best-Practices",
			"score": 2
		},
		{
			"check": "Fuzzing",
			"score": 10
		},
		{
			"check": "License",
			"score": 9
		},
		{
			"check": "Signed-Releases",
			"score": -1
		},
		{
			"check": "Branch-Protection",
			"score": -1
		},
		{
			"check": "Vulnerabilities",
			"score": 10
		},
		{
			"check": "SAST",
			"score": 0
		}
		],
		"aggregateScore": 5.400000095367432,
		"timeScanned": "2025-06-23T00:00:00Z",
		"scorecardVersion": "v5.2.1-9-g59ed1b6b",
		"scorecardCommit": "59ed1b6b04d3ba5a721d494d4a277cdca33659e1",
		"origin": "",
		"collector": "",
		"documentRef": ""
	},
	"IsDepPackages": [
		{
		"CurrentPackageInput": {
			"type": "golang",
			"namespace": "github.com/spdx",
			"name": "tools-golang",
			"version": "v0.1.0",
			"qualifiers": null,
			"subpath": ""
		},
		"DepPackageInput": {
			"type": "golang",
			"namespace": "github.com/spdx",
			"name": "gordf",
			"version": "v0.0.0-20201111095634-7098f93598fb",
			"qualifiers": null,
			"subpath": ""
		},
		"IsDependency": {
			"dependencyType": "DIRECT",
			"justification": "dependency data collected via deps.dev",
			"origin": "",
			"collector": "",
			"documentRef": ""
		}
		}
	],
	"DepPackages": [
		{
		"CurrentPackage": {
			"type": "golang",
			"namespace": "github.com/spdx",
			"name": "gordf",
			"version": "v0.0.0-20201111095634-7098f93598fb",
			"qualifiers": null,
			"subpath": ""
		},
		"Source": {
			"type": "git",
			"namespace": "github.com/spdx",
			"name": "gordf",
			"tag": null,
			"commit": null
		},
		"Scorecard": {
			"checks": [
			{
				"check": "Packaging",
				"score": -1
			},
			{
				"check": "Binary-Artifacts",
				"score": 10
			},
			{
				"check": "Dangerous-Workflow",
				"score": 10
			},
			{
				"check": "Code-Review",
				"score": 0
			},
			{
				"check": "Maintained",
				"score": 0
			},
			{
				"check": "Token-Permissions",
				"score": 0
			},
			{
				"check": "CII-Best-Practices",
				"score": 0
			},
			{
				"check": "Pinned-Dependencies",
				"score": 2
			},
			{
				"check": "Security-Policy",
				"score": 0
			},
			{
				"check": "Fuzzing",
				"score": 0
			},
			{
				"check": "License",
				"score": 10
			},
			{
				"check": "Signed-Releases",
				"score": -1
			},
			{
				"check": "Branch-Protection",
				"score": 0
			},
			{
				"check": "SAST",
				"score": 0
			},
			{
				"check": "Vulnerabilities",
				"score": 10
			}
			],
			"aggregateScore": 3.5999999046325684,
			"timeScanned": "2025-06-23T00:00:00Z",
			"scorecardVersion": "v5.2.1-9-g59ed1b6b",
			"scorecardCommit": "59ed1b6b04d3ba5a721d494d4a277cdca33659e1",
			"origin": "",
			"collector": "",
			"documentRef": ""
		},
		"IsDepPackages": null,
		"DepPackages": null,
		"UpdateTime": "2025-07-01T18:23:19.225447Z"
		}
	],
	"UpdateTime": "2025-07-01T18:23:19.225376Z"
	}`

	CollectedForeignTypesNoDeps = `{
		"CurrentPackage":{
		   "name":"foreign-types",
		   "namespace":"",
		   "qualifiers":null,
		   "subpath":"",
		   "type":"cargo",
		   "version":"0.3.2"
		},
		"Scorecard":{
		   "aggregateScore":4.599999904632568,
		   "checks":[
			  {
				 "check":"Maintained",
				 "score":5
			  },
			  {
				 "check":"CII-Best-Practices",
				 "score":0
			  },
			  {
				 "check":"Signed-Releases",
				 "score":-1
			  },
			  {
				 "check":"Packaging",
				 "score":-1
			  },
			  {
				 "check":"Dangerous-Workflow",
				 "score":10
			  },
			  {
				 "check":"Binary-Artifacts",
				 "score":10
			  },
			  {
				 "check":"Token-Permissions",
				 "score":0
			  },
			  {
				 "check":"Pinned-Dependencies",
				 "score":7
			  },
			  {
				 "check":"Fuzzing",
				 "score":0
			  },
			  {
				 "check":"Vulnerabilities",
				 "score":10
			  },
			  {
				 "check":"Branch-Protection",
				 "score":0
			  },
			  {
				 "check":"License",
				 "score":10
			  },
			  {
				 "check":"Security-Policy",
				 "score":0
			  }
		   ],
		   "collector":"",
		   "origin":"",
		   "scorecardCommit":"6c5de2c32a4b8f60211e8e8eb94f8d3370a11b93",
		   "scorecardVersion":"v4.10.5-77-g6c5de2c",
		   "timeScanned":"2022-11-21T17:45:50.52Z"
		},
		"Source":{
		   "commit":null,
		   "name":"foreign-types",
		   "namespace":"github.com/sfackler",
		   "tag":null,
		   "type":"git"
		},
		"UpdateTime":"2022-11-21T17:45:50.52Z"
	 }`
	CollectedForeignTypes = `{
		"CurrentPackage":{
		   "name":"foreign-types",
		   "namespace":"",
		   "qualifiers":null,
		   "subpath":"",
		   "type":"cargo",
		   "version":"0.3.2"
		},
		"DepPackages":[
		   {
			  "CurrentPackage":{
				 "name":"foreign-types-shared",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"cargo",
				 "version":"0.1.1"
			  },
			  "DepPackages":null,
			  "IsDepPackages":null,
			  "Scorecard":{
				 "aggregateScore":4.599999904632568,
				 "checks":[
					{
					   "check":"Maintained",
					   "score":5
					},
					{
					   "check":"CII-Best-Practices",
					   "score":0
					},
					{
					   "check":"Signed-Releases",
					   "score":-1
					},
					{
					   "check":"Packaging",
					   "score":-1
					},
					{
					   "check":"Dangerous-Workflow",
					   "score":10
					},
					{
					   "check":"Binary-Artifacts",
					   "score":10
					},
					{
					   "check":"Token-Permissions",
					   "score":0
					},
					{
					   "check":"Pinned-Dependencies",
					   "score":7
					},
					{
					   "check":"Fuzzing",
					   "score":0
					},
					{
					   "check":"Vulnerabilities",
					   "score":10
					},
					{
					   "check":"Branch-Protection",
					   "score":0
					},
					{
					   "check":"License",
					   "score":10
					},
					{
					   "check":"Security-Policy",
					   "score":0
					}
				 ],
				 "collector":"",
				 "origin":"",
				 "scorecardCommit":"6c5de2c32a4b8f60211e8e8eb94f8d3370a11b93",
				 "scorecardVersion":"v4.10.5-77-g6c5de2c",
				 "timeScanned":"2022-11-21T17:45:50.52Z"
			  },
			  "Source":{
				 "commit":null,
				 "name":"foreign-types",
				 "namespace":"github.com/sfackler",
				 "tag":null,
				 "type":"git"
			  },
			  "UpdateTime":"2022-11-21T17:45:50.52Z"
		   }
		],
		"IsDepPackages":[
		   {
			  "CurrentPackageInput":{
				 "name":"foreign-types",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"cargo",
				 "version":"0.3.2"
			  },
			  "DepPackageInput":{
				 "name":"foreign-types-shared",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"cargo",
				 "version":"0.1.1"
			  },
			  "IsDependency":{
				 "collector":"",
				 "dependencyType":"DIRECT",
				 "justification":"dependency data collected via deps.dev",
				 "origin":""
			  }
		   }
		],
		"Scorecard":{
		   "aggregateScore":4.599999904632568,
		   "checks":[
			  {
				 "check":"Maintained",
				 "score":5
			  },
			  {
				 "check":"CII-Best-Practices",
				 "score":0
			  },
			  {
				 "check":"Signed-Releases",
				 "score":-1
			  },
			  {
				 "check":"Packaging",
				 "score":-1
			  },
			  {
				 "check":"Dangerous-Workflow",
				 "score":10
			  },
			  {
				 "check":"Binary-Artifacts",
				 "score":10
			  },
			  {
				 "check":"Token-Permissions",
				 "score":0
			  },
			  {
				 "check":"Pinned-Dependencies",
				 "score":7
			  },
			  {
				 "check":"Fuzzing",
				 "score":0
			  },
			  {
				 "check":"Vulnerabilities",
				 "score":10
			  },
			  {
				 "check":"Branch-Protection",
				 "score":0
			  },
			  {
				 "check":"License",
				 "score":10
			  },
			  {
				 "check":"Security-Policy",
				 "score":0
			  }
		   ],
		   "collector":"",
		   "origin":"",
		   "scorecardCommit":"6c5de2c32a4b8f60211e8e8eb94f8d3370a11b93",
		   "scorecardVersion":"v4.10.5-77-g6c5de2c",
		   "timeScanned":"2022-11-21T17:45:50.52Z"
		},
		"Source":{
		   "commit":null,
		   "name":"foreign-types",
		   "namespace":"github.com/sfackler",
		   "tag":null,
		   "type":"git"
		},
		"UpdateTime":"2022-11-21T17:45:50.52Z"
	 }`
	CollectedYargsParser = `{
		"CurrentPackage":{
		   "name":"yargs-parser",
		   "namespace":"",
		   "qualifiers":null,
		   "subpath":"",
		   "type":"npm",
		   "version":"4.2.1"
		},
		"DepPackages":[
		   {
			  "CurrentPackage":{
				 "name":"camelcase",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"3.0.0"
			  },
			  "DepPackages":null,
			  "IsDepPackages":null,
			  "Scorecard":null,
			  "Source":{
				 "commit":null,
				 "name":"camelcase",
				 "namespace":"github.com/sindresorhus",
				 "tag":null,
				 "type":"git"
			  },
			  "UpdateTime":"2022-11-21T17:45:50.52Z"
		   }
		],
		"IsDepPackages":[
		   {
			  "CurrentPackageInput":{
				 "name":"yargs-parser",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"4.2.1"
			  },
			  "DepPackageInput":{
				 "name":"camelcase",
				 "namespace":"",
				 "qualifiers":null,
				 "subpath":"",
				 "type":"npm",
				 "version":"3.0.0"
			  },
			  "IsDependency":{
				 "collector":"",
				 "dependencyType":"DIRECT",
				 "justification":"dependency data collected via deps.dev",
				 "origin":""
			  }
		   }
		],
		"Scorecard":null,
		"Source":{
		   "commit":null,
		   "name":"yargs-parser",
		   "namespace":"github.com/yargs",
		   "tag":null,
		   "type":"git"
		},
		"UpdateTime":"2022-11-21T17:45:50.52Z"
	 }`

	// OpenVEX

	//go:embed exampledata/open-vex-not-affected.json
	NotAffectedOpenVEXExample []byte

	NotAffectedOpenVexIngest = []assembler.VexIngest{
		{
			Pkg: &generated.PkgInputSpec{
				Name:      "git",
				Version:   strP("sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"),
				Namespace: strP(""),
				Type:      "oci",
				Subpath:   strP(""),
			},
			Artifact: nil,
			Vulnerability: &generated.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "cve-2023-12345",
			},
			VexData: &generated.VexStatementInputSpec{
				KnownSince:       parseRfc3339("2023-01-09T21:23:03.579712389-06:00"),
				Origin:           "https://openvex.dev/docs/public/vex-a06f9de1ad1b1e555a33b2d0c1e7e6ecc4dc1800ff457c61ea09d8e97670d2a3",
				VexJustification: generated.VexJustificationInlineMitigationsAlreadyExist,
				Status:           generated.VexStatusNotAffected,
				Statement:        "Included git is mitigated against CVE-2023-12345 !",
			},
		},
	}

	//go:embed exampledata/open-vex-affected.json
	AffectedOpenVex []byte

	AffectedOpenVexIngest = []assembler.VexIngest{
		{
			Pkg: &generated.PkgInputSpec{
				Name:      "bash",
				Version:   strP("1.0.0"),
				Namespace: strP("wolfi"),
				Type:      "apk",
				Subpath:   strP(""),
			},
			Artifact: nil,
			Vulnerability: &generated.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "cve-1234-5678",
			},
			VexData: &generated.VexStatementInputSpec{
				KnownSince:       parseRfc3339("2023-01-19T02:36:03.290252574-06:00"),
				Origin:           "merged-vex-67124ea942ef30e1f42f3f2bf405fbbc4f5a56e6e87684fc5cd957212fa3e025",
				Status:           generated.VexStatusAffected,
				VexJustification: generated.VexJustificationNotProvided,
				Statement:        "This is a test action statement",
			},
		},
	}

	AffectedOpenVEXCertifyVulnIngest = []assembler.CertifyVulnIngest{
		{
			Pkg: &generated.PkgInputSpec{
				Name:      "bash",
				Version:   strP("1.0.0"),
				Namespace: strP("wolfi"),
				Type:      "apk",
				Subpath:   strP(""),
			},
			Vulnerability: &generated.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "cve-1234-5678",
			},
			VulnData: &generated.ScanMetadataInput{
				TimeScanned: parseRfc3339("2023-01-19T02:36:03.290252574-06:00"),
			},
		},
	}

	// CSAF
	//go:embed exampledata/rhsa-csaf.json
	CsafExampleRedHat []byte

	CsafVexIngest = []assembler.VexIngest{
		{
			Pkg: &model.PkgInputSpec{
				Type:       "rpm",
				Namespace:  strP("redhat"),
				Name:       "openssl",
				Version:    strP("1.1.1k-8.el8_6"),
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "arch", Value: "aarch64"}, {Key: "epoch", Value: "1"}},
				Subpath:    strP(""),
			},
			Vulnerability: &model.VulnerabilityInputSpec{Type: "cve", VulnerabilityID: "cve-2023-0286"},
			VexData: &model.VexStatementInputSpec{
				Status:           generated.VexStatusFixed,
				VexJustification: generated.VexJustificationNotProvided,
				Statement: `For details on how to apply this update, which includes the changes described in this advisory, refer to:

https://access.redhat.com/articles/11258

For the update to take effect, all services linked to the OpenSSL library must be restarted, or the system rebooted.`,

				KnownSince: parseRfc3339("2023-03-23T11:14:00Z"),
				Origin:     "RHSA-2023:1441",
			},
		},
		{
			Pkg: &model.PkgInputSpec{
				Type:       "rpm",
				Namespace:  strP("redhat"),
				Name:       "openssl",
				Version:    strP("1.1.1k-7.el8_6"),
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "arch", Value: "x86_64"}, {Key: "epoch", Value: "1"}},
				Subpath:    strP(""),
			},
			Vulnerability: &model.VulnerabilityInputSpec{Type: "cve", VulnerabilityID: "cve-2023-0286"},
			VexData: &model.VexStatementInputSpec{
				Status:           generated.VexStatusAffected,
				VexJustification: generated.VexJustificationNotProvided,
				Statement: `For details on how to apply this update, which includes the changes described in this advisory, refer to:

https://access.redhat.com/articles/11258

For the update to take effect, all services linked to the OpenSSL library must be restarted, or the system rebooted.`,

				KnownSince: parseRfc3339("2023-03-23T11:14:00Z"),
				Origin:     "RHSA-2023:1441",
			},
		},
		{
			Pkg: &model.PkgInputSpec{
				Type:       "rpm",
				Namespace:  strP("redhat"),
				Name:       "nginx",
				Version:    strP("1.20.1-1.module+el8.8.0+20359+9bd89172.1"),
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "arch", Value: "x86_64"}, {Key: "epoch", Value: "1"}},
				Subpath:    strP(""),
			},
			Vulnerability: &model.VulnerabilityInputSpec{Type: "cve", VulnerabilityID: "cve-2023-0286"},
			VexData: &model.VexStatementInputSpec{
				Status:           generated.VexStatusFixed,
				VexJustification: generated.VexJustificationNotProvided,
				Statement: `For details on how to apply this update, which includes the changes described in this advisory, refer to:

https://access.redhat.com/articles/11258

For the update to take effect, all services linked to the OpenSSL library must be restarted, or the system rebooted.`,

				KnownSince: parseRfc3339("2023-03-23T11:14:00Z"),
				Origin:     "RHSA-2023:1441",
			},
		},
	}
	CsafCertifyVulnIngest = []assembler.CertifyVulnIngest{
		{
			Pkg: &model.PkgInputSpec{
				Type:      "rpm",
				Namespace: strP("redhat"),
				Name:      "openssl",
				Version:   strP("1.1.1k-8.el8_6"),
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "arch", Value: "aarch64"},
					{Key: "epoch", Value: "1"},
				},
				Subpath: strP(""),
			},
			Vulnerability: &model.VulnerabilityInputSpec{Type: "NoVuln", VulnerabilityID: ""},
			VulnData: &model.ScanMetadataInput{
				TimeScanned: parseRfc3339("2023-03-23T11:14:00Z"),
			},
		},
		{
			Pkg: &model.PkgInputSpec{
				Type:      "rpm",
				Namespace: strP("redhat"),
				Name:      "openssl",
				Version:   strP("1.1.1k-7.el8_6"),
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "arch", Value: "x86_64"},
					{Key: "epoch", Value: "1"},
				},
				Subpath: strP(""),
			},
			Vulnerability: &model.VulnerabilityInputSpec{Type: "cve", VulnerabilityID: "cve-2023-0286"},
			VulnData: &model.ScanMetadataInput{
				TimeScanned: parseRfc3339("2023-03-23T11:14:00Z"),
			},
		},
		{
			Pkg: &model.PkgInputSpec{
				Type:       "rpm",
				Namespace:  strP("redhat"),
				Name:       "nginx",
				Version:    strP("1.20.1-1.module+el8.8.0+20359+9bd89172.1"),
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "arch", Value: "x86_64"}, {Key: "epoch", Value: "1"}},
				Subpath:    strP(""),
			},
			Vulnerability: &model.VulnerabilityInputSpec{Type: "NoVuln", VulnerabilityID: ""},
			VulnData: &model.ScanMetadataInput{
				TimeScanned: parseRfc3339("2023-03-23T11:14:00Z"),
			},
		},
	}

	IngestPredicatesExamplePredicates = assembler.IngestPredicates{
		CertifyScorecard: []assembler.CertifyScorecardIngest{
			{
				Source: &generated.SourceInputSpec{
					Type:      "git",
					Namespace: "github.com/kubernetes",
					Name:      "kubernetes",
					Commit:    ptrfrom.String("5835544ca568b757a8ecae5c153f317e5736700e"),
				},
				Scorecard: &generated.ScorecardInputSpec{
					Checks: []generated.ScorecardCheckInputSpec{
						{Check: "Binary-Artifacts", Score: 10},
						{Check: "CI-Tests", Score: 10},
						{Check: "Code-Review", Score: 7},
						{Check: "Dangerous-Workflow", Score: 10},
						{Check: "License", Score: 10},
						{Check: "Pinned-Dependencies", Score: 2},
						{Check: "Security-Policy", Score: 10},
						{Check: "Token-Permissions", Score: 10},
						{Check: "Vulnerabilities", Score: 10},
					},
					AggregateScore:   8.9,
					TimeScanned:      toTime("2022-10-06"),
					ScorecardVersion: "v4.7.0",
					ScorecardCommit:  "7cd6406aef0b80a819402e631919293d5eb6adcf",
				},
			},
		},
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg:    topLevelPack,
				DepPkg: baselayoutPack,
				IsDependency: &generated.IsDependencyInputSpec{
					DependencyType: generated.DependencyTypeUnknown,
					Justification:  "top level package dependency",
				},
			},
			{
				Pkg:    topLevelPack,
				DepPkg: baselayoutdataPack,
				IsDependency: &generated.IsDependencyInputSpec{
					DependencyType: generated.DependencyTypeUnknown,
					Justification:  "top level package dependency",
				},
			},
		},
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg:      worldFilePack,
				Artifact: worldFileArtifact,
				IsOccurrence: &generated.IsOccurrenceInputSpec{
					Justification: "spdx file with checksum",
				},
			},
			{
				Pkg:      rootFilePack,
				Artifact: rootFileArtifact,
				IsOccurrence: &generated.IsOccurrenceInputSpec{
					Justification: "spdx file with checksum",
				},
			},
		},
		HasSBOM: []assembler.HasSBOMIngest{
			{
				Pkg: topLevelPack,
				HasSBOM: &generated.HasSBOMInputSpec{
					Uri:              "TestSource",
					Algorithm:        "sha256",
					Digest:           "8b5e8212cae084f92ff91f8625a50ea1070738cfc68ecca08bf04d64f64b9feb",
					DownloadLocation: "TestSource",
				},
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &generated.ArtifactInputSpec{
					Algorithm: "sha256",
					Digest:    "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
				},
				Builder: &generated.BuilderInputSpec{
					Uri: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v0.0.1",
				},
				Materials: []generated.ArtifactInputSpec{{
					Algorithm: "gitCommit",
					Digest:    "c27d339ee6075c1f744c5d4b200f7901aad2c369",
				}},
				HasSlsa: &generated.SLSAInputSpec{
					BuildType:   "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
					SlsaVersion: "https://slsa.dev/provenance/v1",
					StartedOn:   &slsaStartTime,
					SlsaPredicate: []generated.SLSAPredicateInputSpec{
						{Key: "slsa.buildDefinition.buildType", Value: "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"},
						{Key: "slsa.buildDefinition.externalParameters.inputs.build_id", Value: "1.23456768e+08"},
						{Key: "slsa.buildDefinition.externalParameters.inputs.deploy_target", Value: "deployment_sys_1a"},
						{Key: "slsa.buildDefinition.externalParameters.inputs.perform_deploy", Value: "true"},
						{Key: "slsa.buildDefinition.externalParameters.vars.MASCOT", Value: "Mona"},
						{Key: "slsa.buildDefinition.externalParameters.workflow.path", Value: ".github/workflow/release.yml"},
						{Key: "slsa.buildDefinition.externalParameters.workflow.ref", Value: "refs/heads/main"},
						{Key: "slsa.buildDefinition.externalParameters.workflow.repository", Value: "https://github.com/octocat/hello-world"},
						{Key: "slsa.buildDefinition.internalParameters.github.actor_id", Value: "1234567"},
						{Key: "slsa.buildDefinition.internalParameters.github.event_name", Value: "workflow_dispatch"},
						{Key: "slsa.buildDefinition.resolvedDependencies.0.digest.gitCommit", Value: "c27d339ee6075c1f744c5d4b200f7901aad2c369"},
						{Key: "slsa.buildDefinition.resolvedDependencies.0.uri", Value: "git+https://github.com/octocat/hello-world@refs/heads/main"},
						{Key: "slsa.buildDefinition.resolvedDependencies.1.uri", Value: "https://github.com/actions/virtual-environments/releases/tag/ubuntu20/20220515.1"},
						{Key: "slsa.runDetails.builder.id", Value: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v0.0.1"},
						{Key: "slsa.runDetails.metadata.invocationId", Value: "https://github.com/octocat/hello-world/actions/runs/1536140711/attempts/1"},
						{Key: "slsa.runDetails.metadata.startedOn", Value: "2023-01-01T12:34:56Z"},
					},
				},
			},
		},
		CertifyVuln: []assembler.CertifyVulnIngest{
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "cve-2023-1944",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    parseRfc3339("2022-11-21T17:45:50.52Z"),
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-8489-44mv-ggj8",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    parseRfc3339("2022-11-21T17:45:50.52Z"),
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-fxph-q3j8-mv87",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    parseRfc3339("2022-11-21T17:45:50.52Z"),
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-jfh8-c2jp-5v3q",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    parseRfc3339("2022-11-21T17:45:50.52Z"),
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-p6xc-xr62-6r2g",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    parseRfc3339("2022-11-21T17:45:50.52Z"),
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-vwqq-5vrc-xw9h",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    parseRfc3339("2022-11-21T17:45:50.52Z"),
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
		},
		VulnEqual: []assembler.VulnEqualIngest{
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "cve-2023-1944",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "cve-2023-1944",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-7rjr-3q55-vv33",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-7rjr-3q55-vv33",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-8489-44mv-ggj8",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-8489-44mv-ggj8",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-fxph-q3j8-mv87",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-fxph-q3j8-mv87",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-jfh8-c2jp-5v3q",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-jfh8-c2jp-5v3q",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-p6xc-xr62-6r2g",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-p6xc-xr62-6r2g",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
		},
		CertifyBad: []assembler.CertifyBadIngest{
			{
				Pkg:          topLevelPack,
				PkgMatchFlag: generated.MatchFlags{Pkg: "SPECIFIC_VERSION"},
				CertifyBad: &generated.CertifyBadInputSpec{
					Justification: "bad package",
				},
			},
			{
				Src: &generated.SourceInputSpec{
					Type:      "git",
					Namespace: "github.com/kubernetes",
					Name:      "kubernetes",
					Commit:    ptrfrom.String("5835544ca568b757a8ecae5c153f317e5736700e"),
				},
				CertifyBad: &generated.CertifyBadInputSpec{
					Justification: "bad source",
				},
			},
			{
				Artifact: &generated.ArtifactInputSpec{
					Algorithm: "sha256",
					Digest:    "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
				},
				CertifyBad: &generated.CertifyBadInputSpec{
					Justification: "bad artifact",
				},
			},
		},
		CertifyGood: []assembler.CertifyGoodIngest{
			{
				Pkg:          topLevelPack,
				PkgMatchFlag: generated.MatchFlags{Pkg: "SPECIFIC_VERSION"},
				CertifyGood: &generated.CertifyGoodInputSpec{
					Justification: "good package",
				},
			},
			{
				Src: &generated.SourceInputSpec{
					Type:      "git",
					Namespace: "github.com/kubernetes",
					Name:      "kubernetes",
					Commit:    ptrfrom.String("5835544ca568b757a8ecae5c153f317e5736700e"),
				},
				CertifyGood: &generated.CertifyGoodInputSpec{
					Justification: "good source",
				},
			},
			{
				Artifact: &generated.ArtifactInputSpec{
					Algorithm: "sha256",
					Digest:    "1234e40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
				},
				CertifyGood: &generated.CertifyGoodInputSpec{
					Justification: "good artifact",
				},
			},
		},
		HasSourceAt: []assembler.HasSourceAtIngest{
			{
				Pkg:          topLevelPack,
				PkgMatchFlag: generated.MatchFlags{Pkg: "SPECIFIC_VERSION"},
				Src: &generated.SourceInputSpec{
					Type:      "git",
					Namespace: "github.com/kubernetes",
					Name:      "kubernetes",
					Commit:    ptrfrom.String("5835544ca568b757a8ecae5c153f317e5736700e"),
				},
				HasSourceAt: &generated.HasSourceAtInputSpec{
					KnownSince:    parseRfc3339("2022-09-21T17:45:50.52Z"),
					Justification: "package at this source",
				},
			},
		},
		HashEqual: []assembler.HashEqualIngest{
			{
				Artifact: &generated.ArtifactInputSpec{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				EqualArtifact: &generated.ArtifactInputSpec{
					Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
					Algorithm: "sha1",
				},
				HashEqual: &generated.HashEqualInputSpec{
					Justification: "these sha1 and sha256 artifacts are the same",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
		PkgEqual: []assembler.PkgEqualIngest{
			{
				Pkg: &generated.PkgInputSpec{
					Type:       "conan",
					Namespace:  ptrfrom.String("openssl.org"),
					Name:       "openssl",
					Version:    ptrfrom.String("3.0.3"),
					Qualifiers: []generated.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
					Subpath:    ptrfrom.String(""),
				},
				EqualPkg: &generated.PkgInputSpec{
					Type:       "conan",
					Namespace:  ptrfrom.String("openssl.org"),
					Name:       "openssl2",
					Version:    ptrfrom.String("3.0.3"),
					Qualifiers: []generated.PackageQualifierInputSpec{},
					Subpath:    ptrfrom.String(""),
				},
				PkgEqual: &generated.PkgEqualInputSpec{
					Justification: "these two openssl packages are the same",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
		Vex: []assembler.VexIngest{
			{
				Pkg: &generated.PkgInputSpec{
					Type:       "conan",
					Namespace:  ptrfrom.String("openssl.org"),
					Name:       "openssl",
					Version:    ptrfrom.String("3.0.3"),
					Qualifiers: []generated.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
					Subpath:    ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-h45f-rjvw-2rv2",
				},
				VexData: &generated.VexStatementInputSpec{
					Status:           generated.VexStatusNotAffected,
					VexJustification: generated.VexJustificationComponentNotPresent,
					KnownSince:       parseRfc3339("2022-11-21T17:45:50.52Z"),
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
			},
			{
				Artifact: &generated.ArtifactInputSpec{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "cve-2018-15710",
				},
				VexData: &generated.VexStatementInputSpec{
					Status:           generated.VexStatusUnderInvestigation,
					VexJustification: generated.VexJustificationNotProvided,
					KnownSince:       parseRfc3339("2022-11-21T17:45:50.52Z"),
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
			},
			{
				Artifact: &generated.ArtifactInputSpec{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "cve-2018-43610",
				},
				VexData: &generated.VexStatementInputSpec{
					Status:           generated.VexStatusNotAffected,
					VexJustification: generated.VexJustificationNotProvided,
					Statement:        "this artifact is not vulnerable to this CVE",
					StatusNotes:      "status not affected because code not in execution path",
					KnownSince:       parseRfc3339("2022-11-21T17:45:50.52Z"),
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
			},
		},
	}
)

var IngestPredicatesCmpOpts = []cmp.Option{
	cmpopts.EquateEmpty(),
	cmpopts.SortSlices(certifyScorecardLess),
	cmpopts.SortSlices(isDependencyLess),
	cmpopts.SortSlices(isOccurenceLess),
	cmpopts.SortSlices(packageQualifierInputSpecLess),
	cmpopts.SortSlices(psaInputSpecLess),
	cmpopts.SortSlices(slsaPredicateInputSpecLess),
	cmpopts.SortSlices(certifyLegalInputSpecLess),
	cmpopts.SortSlices(licenseInputSpecLess),
	cmpopts.SortSlices(hasMetadataLess),
	cmpopts.SortSlices(vexLess),
	cmpopts.SortSlices(certifyVulnLess),
}

func certifyScorecardLess(e1, e2 assembler.CertifyScorecardIngest) bool {
	return gLess(e1, e2)
}

func isDependencyLess(a, b assembler.IsDependencyIngest) bool {
	if strings.Compare(a.Pkg.Name, b.Pkg.Name) != 0 {
		return a.Pkg.Name < b.Pkg.Name
	}
	if d := strings.Compare(a.DepPkg.Name, b.DepPkg.Name); d != 0 {
		return a.DepPkg.Name < b.DepPkg.Name
	}
	return false
}

func isOccurenceLess(e1, e2 assembler.IsOccurrenceIngest) bool {
	return gLess(e1, e2)
}

func packageQualifierInputSpecLess(e1, e2 model.PackageQualifierInputSpec) bool {
	return gLess(e1, e2)
}

func psaInputSpecLess(e1, e2 model.ArtifactInputSpec) bool {
	return gLess(e1, e2)
}

func slsaPredicateInputSpecLess(e1, e2 model.SLSAPredicateInputSpec) bool {
	return gLess(e1, e2)
}

func certifyLegalInputSpecLess(e1, e2 assembler.CertifyLegalIngest) bool {
	return gLess(e1, e2)
}

func licenseInputSpecLess(e1, e2 generated.LicenseInputSpec) bool {
	return gLess(e1, e2)
}

func hasMetadataLess(e1, e2 assembler.HasMetadataIngest) bool {
	return gLess(e1, e2)
}

func vexLess(e1, e2 assembler.VexIngest) bool {
	return gLess(e1, e2)
}

func certifyVulnLess(e1, e2 assembler.CertifyVulnIngest) bool {
	return gLess(e1, e2)
}

func gLess(e1, e2 any) bool {
	s1, _ := json.Marshal(e1)
	s2, _ := json.Marshal(e2)
	return string(s1) < string(s2)
}

func strP(s string) *string {
	return &s
}

func parseRfc3339(s string) time.Time {
	time, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return time
}

func toTime(s string) time.Time {
	timeScanned, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return timeScanned
}

func parseUTCTime(s string) time.Time {
	timeScanned, err := time.Parse("2006-01-02T15:04:05Z", s)
	if err != nil {
		panic(err)
	}
	return timeScanned
}
