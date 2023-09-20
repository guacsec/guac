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

package helpers

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestIngestCertifyGood(t *testing.T) {
	tests := []struct {
		Name     string
		Packages []*model.Package
		Want     []*model.PackageIDs
	}{{
		Name: "Single package",
		Packages: []*model.Package{{
			ID: "1",
			Namespaces: []*model.PackageNamespace{{
				ID: "2",
				Names: []*model.PackageName{{
					ID: "3",
					Versions: []*model.PackageVersion{{
						ID: "4",
					}},
				}},
			}},
		}},
		Want: []*model.PackageIDs{{
			PackageTypeID:      "1",
			PackageNamespaceID: "2",
			PackageNameID:      "3",
			PackageVersionID:   "4",
		}},
	}, {
		Name: "Multiple packages",
		Packages: []*model.Package{{
			ID: "1",
			Namespaces: []*model.PackageNamespace{{
				ID: "2",
				Names: []*model.PackageName{{
					ID: "3",
					Versions: []*model.PackageVersion{{
						ID: "4",
					}},
				}},
			}},
		}, {
			ID: "5",
			Namespaces: []*model.PackageNamespace{{
				ID: "6",
				Names: []*model.PackageName{{
					ID: "7",
					Versions: []*model.PackageVersion{{
						ID: "8",
					}},
				}},
			}},
		}},
		Want: []*model.PackageIDs{{
			PackageTypeID:      "1",
			PackageNamespaceID: "2",
			PackageNameID:      "3",
			PackageVersionID:   "4",
		}, {
			PackageTypeID:      "5",
			PackageNamespaceID: "6",
			PackageNameID:      "7",
			PackageVersionID:   "8",
		}},
	}, {
		Name: "Package Tree",
		Packages: []*model.Package{{
			ID: "1",
			Namespaces: []*model.PackageNamespace{{
				ID: "2",
				Names: []*model.PackageName{{
					ID: "3",
					Versions: []*model.PackageVersion{{
						ID: "4",
					}, {
						ID: "5",
					}},
				}, {
					ID: "6",
					Versions: []*model.PackageVersion{{
						ID: "7",
					}, {
						ID: "8",
					}},
				}},
			}, {
				ID: "9",
				Names: []*model.PackageName{{
					ID: "10",
					Versions: []*model.PackageVersion{{
						ID: "11",
					}, {
						ID: "12",
					}},
				}, {
					ID: "13",
					Versions: []*model.PackageVersion{{
						ID: "14",
					}, {
						ID: "15",
					}},
				}},
			}},
		}, {
			ID: "16",
			Namespaces: []*model.PackageNamespace{{
				ID: "17",
				Names: []*model.PackageName{{
					ID: "18",
					Versions: []*model.PackageVersion{{
						ID: "19",
					}, {
						ID: "20",
					}},
				}, {
					ID: "21",
					Versions: []*model.PackageVersion{{
						ID: "22",
					}, {
						ID: "23",
					}},
				}},
			}, {
				ID: "24",
				Names: []*model.PackageName{{
					ID: "25",
					Versions: []*model.PackageVersion{{
						ID: "26",
					}, {
						ID: "27",
					}},
				}, {
					ID: "28",
					Versions: []*model.PackageVersion{{
						ID: "29",
					}, {
						ID: "30",
					}},
				}},
			}},
		}},
		Want: []*model.PackageIDs{{
			PackageTypeID:      "1",
			PackageNamespaceID: "2",
			PackageNameID:      "3",
			PackageVersionID:   "4",
		}, {
			PackageTypeID:      "1",
			PackageNamespaceID: "2",
			PackageNameID:      "3",
			PackageVersionID:   "5",
		}, {
			PackageTypeID:      "1",
			PackageNamespaceID: "2",
			PackageNameID:      "6",
			PackageVersionID:   "7",
		}, {
			PackageTypeID:      "1",
			PackageNamespaceID: "2",
			PackageNameID:      "6",
			PackageVersionID:   "8",
		}, {
			PackageTypeID:      "1",
			PackageNamespaceID: "9",
			PackageNameID:      "10",
			PackageVersionID:   "11",
		}, {
			PackageTypeID:      "1",
			PackageNamespaceID: "9",
			PackageNameID:      "10",
			PackageVersionID:   "12",
		}, {
			PackageTypeID:      "1",
			PackageNamespaceID: "9",
			PackageNameID:      "13",
			PackageVersionID:   "14",
		}, {
			PackageTypeID:      "1",
			PackageNamespaceID: "9",
			PackageNameID:      "13",
			PackageVersionID:   "15",
		}, {
			PackageTypeID:      "16",
			PackageNamespaceID: "17",
			PackageNameID:      "18",
			PackageVersionID:   "19",
		}, {
			PackageTypeID:      "16",
			PackageNamespaceID: "17",
			PackageNameID:      "18",
			PackageVersionID:   "20",
		}, {
			PackageTypeID:      "16",
			PackageNamespaceID: "17",
			PackageNameID:      "21",
			PackageVersionID:   "22",
		}, {
			PackageTypeID:      "16",
			PackageNamespaceID: "17",
			PackageNameID:      "21",
			PackageVersionID:   "23",
		}, {
			PackageTypeID:      "16",
			PackageNamespaceID: "24",
			PackageNameID:      "25",
			PackageVersionID:   "26",
		}, {
			PackageTypeID:      "16",
			PackageNamespaceID: "24",
			PackageNameID:      "25",
			PackageVersionID:   "27",
		}, {
			PackageTypeID:      "16",
			PackageNamespaceID: "24",
			PackageNameID:      "28",
			PackageVersionID:   "29",
		}, {
			PackageTypeID:      "16",
			PackageNamespaceID: "24",
			PackageNameID:      "28",
			PackageVersionID:   "30",
		}},
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result := GetPackageAsIds(test.Packages)
			if diff := cmp.Diff(test.Want, result); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
