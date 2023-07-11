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

package arangodb

import (
	"context"
	"fmt"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO(lumjjb): add source when it is implemented in arango backend
func (c *arangoClient) FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error) {

	queryValues := map[string]any{}
	queryValues["searchText"] = searchText
	query := `

FOR doc in GuacSearch
SEARCH PHRASE(doc.guacKey, @searchText, "text_en") || PHRASE(doc.guacKey, @searchText, "customgram") || doc.digest == @searchText

LET parsedDoc =
    IS_SAME_COLLECTION(doc, "pkgNames") ?
    // pkgNames case
    (
        FOR pNs in pkgNamespaces
          FILTER pNs._id == doc._parent

        FOR pType in pkgTypes
          FILTER pType._id == pNs._parent

        RETURN {
          'nodeType': 'pkgName',
          'id': doc._id,
          'pkgName': {
              'type': pType.type,
              'namespace': pNs.namespace,
              'name': doc.name
          }
        }
    ) : IS_SAME_COLLECTION(doc, "pkgVersions") ?
    // pkgVersions case
    (
        FOR pName in pkgNames
          FILTER pName._id == doc._parent
        FOR pNs in pkgNamespaces
          FILTER pNs._id == pName._parent
        FOR pType in pkgTypes
          FILTER pType._id == pNs._parent

        RETURN {
          'nodeType': 'pkgVersion',
          'id': doc._id,
          'pkgVersion': {
              'type': pType.type,
              'namespace': pNs.namespace,
              'name': pName.name,
              'version': doc.version,
              'subpath': doc.subpath,
              'qualifier_list': doc.qualifier_list
          }
        }
    ) : IS_SAME_COLLECTION(doc, "srcNames") ?
    // srcNames case
    (
        FOR sNs in srcNamespaces
          FILTER sNs._id == doc._parent
        FOR sType in srcTypes
          FILTER sType._id == sNs._parent

        RETURN {
          'nodeType': 'SrcName',
          'id': doc._id,
          'srcName': {
              'type': sType.type,
              'namespace': sNs.namespace,
              'name': doc.name,
              'commit': doc.commit,
              'tag': doc.tag
          }
        }
    )
    :
    // Artifact case
    (RETURN {
        'nodeType': 'artifact',
         'id': doc._id,
         'artifact': {
            'algorithm': doc.algorithm,
            'digest': doc.digest
         }
    })


RETURN {
"parsedDoc": parsedDoc
}

`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, queryValues, "FindSoftware")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}
	defer cursor.Close()

	type parsedDoc struct {
		NodeType string `json:"nodeType"`
		Id       string `json:"id"`
		PkgName  *struct {
			PkgType   string `json:"type"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"pkgName,omitempty"`
		PkgVersion *struct {
			PkgType       string      `json:"type"`
			Namespace     string      `json:"namespace"`
			Name          string      `json:"name"`
			Version       string      `json:"version"`
			Subpath       string      `json:"subpath"`
			QualifierList interface{} `json:"qualifier_list"`
		} `json:"pkgVersion,omitempty"`
		SrcName *struct {
			SrcType   string `json:"type"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			Commit    string `json:"commit"`
			Tag       string `json:"tag"`
		} `json:"srcName,omitempty"`
		Artifact *model.Artifact `json:"artifact,omitempty"`
	}

	type collectedData struct {
		ParsedDoc []parsedDoc `json:"parsedDoc"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to run search: %w, values: %v", err, queryValues)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var results []model.PackageSourceOrArtifact
	for _, createdValue := range createdValues {
		for _, d := range createdValue.ParsedDoc {
			switch d.NodeType {
			case "artifact":
				a := d.Artifact
				if a == nil {
					return nil, fmt.Errorf("failed to parse result of artifact, got nil when expected non-nil")
				}
				results = append(results, a)
			case "pkgVersion":
				p := d.PkgVersion
				if p == nil {
					return nil, fmt.Errorf("failed to parse result of pkgVersion, got nil when expected non-nil")
				}
				pkg, err := generateModelPackage(p.PkgType, p.Namespace, p.Name, p.Version, p.Subpath, p.QualifierList)
				if err != nil {
					return nil, fmt.Errorf("failed to get model.package with err: %w", err)
				}
				results = append(results, pkg)
			case "pkgName":
				p := d.PkgName
				if p == nil {
					return nil, fmt.Errorf("failed to parse result of pkgName, got nil when expected non-nil")
				}
				pkg, err := generateModelPackage(p.PkgType, p.Namespace, p.Name, nil, nil, nil)
				if err != nil {
					return nil, fmt.Errorf("failed to get model.package with err: %w", err)
				}
				results = append(results, pkg)
			}
		}
	}
	return results, nil
}
