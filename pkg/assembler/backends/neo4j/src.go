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

package neo4jBackend

import (
	"context"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// scrNode represents the top level src->Type->Namespace->Name
type srcNode struct {
}

func (sn *srcNode) Type() string {
	return "Src"
}

func (sn *srcNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["src"] = "src"
	return properties
}

func (sn *srcNode) PropertyNames() []string {
	fields := []string{"src"}
	return fields
}

func (sn *srcNode) IdentifiablePropertyNames() []string {
	return []string{"src"}
}

type srcType struct {
	srcType string
}

func (st *srcType) Type() string {
	return "SrcType"
}

func (st *srcType) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["type"] = st.srcType
	return properties
}

func (st *srcType) PropertyNames() []string {
	fields := []string{"type"}
	return fields
}

func (st *srcType) IdentifiablePropertyNames() []string {
	return []string{"type"}
}

type srcNamespace struct {
	namespace string
}

func (sn *srcNamespace) Type() string {
	return "SrcNamespace"
}

func (sn *srcNamespace) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["namespace"] = sn.namespace
	return properties
}

func (sn *srcNamespace) PropertyNames() []string {
	fields := []string{"namespace"}
	return fields
}

func (sn *srcNamespace) IdentifiablePropertyNames() []string {
	return []string{"namespace"}
}

type srcName struct {
	name   string
	tag    string
	commit string
}

func (sn *srcName) Type() string {
	return "SrcName"
}

func (sn *srcName) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = sn.name
	properties["tag"] = sn.tag
	properties["commit"] = sn.commit
	return properties
}

func (sn *srcName) PropertyNames() []string {
	fields := []string{"name", "tag", "commit"}
	return fields
}

func (sn *srcName) IdentifiablePropertyNames() []string {
	return []string{"name", "tag", "commit"}
}

type srcToType struct {
	src     *srcNode
	srcType *srcType
}

func (e *srcToType) Type() string {
	return "SrcHasType"
}

func (e *srcToType) Nodes() (v, u assembler.GuacNode) {
	return e.src, e.srcType
}

func (e *srcToType) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *srcToType) PropertyNames() []string {
	return []string{}
}

func (e *srcToType) IdentifiablePropertyNames() []string {
	return []string{}
}

type srcTypeToNamespace struct {
	srcType   *srcType
	namespace *srcNamespace
}

func (e *srcTypeToNamespace) Type() string {
	return "SrcHasNamespace"
}

func (e *srcTypeToNamespace) Nodes() (v, u assembler.GuacNode) {
	return e.srcType, e.namespace
}

func (e *srcTypeToNamespace) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *srcTypeToNamespace) PropertyNames() []string {
	return []string{}
}

func (e *srcTypeToNamespace) IdentifiablePropertyNames() []string {
	return []string{}
}

type srcNamespaceToName struct {
	namespace *srcNamespace
	name      *srcName
}

func (e *srcNamespaceToName) Type() string {
	return "SrcHasName"
}

func (e *srcNamespaceToName) Nodes() (v, u assembler.GuacNode) {
	return e.namespace, e.name
}

func (e *srcNamespaceToName) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *srcNamespaceToName) PropertyNames() []string {
	return []string{}
}

func (e *srcNamespaceToName) IdentifiablePropertyNames() []string {
	return []string{}
}

func (c *neo4jClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {

	// fields: [type namespaces namespaces.namespace namespaces.names namespaces.names.name namespaces.names.tag namespaces.names.commit]
	fields := getPreloads(ctx)

	nameRequired := false
	namespaceRequired := false
	for _, f := range fields {
		if f == namespaces {
			namespaceRequired = true
		}
		if f == names {
			nameRequired = true
		}
	}

	if !namespaceRequired && !nameRequired {
		return c.sourcesType(ctx, sourceSpec)
	} else if namespaceRequired && !nameRequired {
		return c.sourcesNamespace(ctx, sourceSpec)
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	if sourceSpec.Commit != nil && sourceSpec.Tag != nil {
		if *sourceSpec.Commit != "" || *sourceSpec.Tag != "" {
			return nil, gqlerror.Errorf("Passing both commit and tag selectors is an error")
		}
	}

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	sb.WriteString("MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)-[:SrcHasName]->(name:SrcName)")

	setSrcMatchValues(&sb, sourceSpec, false, &firstMatch, queryValues)

	sb.WriteString(" RETURN type.type, namespace.namespace, name.name, name.tag, name.commit")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			srcTypes := map[string]map[string][]*model.SourceName{}
			for result.Next() {

				commitString := result.Record().Values[4].(string)
				tagString := result.Record().Values[3].(string)
				nameString := result.Record().Values[2].(string)
				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				srcName := &model.SourceName{
					Name:   nameString,
					Tag:    &tagString,
					Commit: &commitString,
				}
				if srcNamespaces, ok := srcTypes[typeString]; ok {
					srcNamespaces[namespaceString] = append(srcNamespaces[namespaceString], srcName)
				} else {
					srcNamespaces := map[string][]*model.SourceName{}
					srcNamespaces[namespaceString] = append(srcNamespaces[namespaceString], srcName)
					srcTypes[typeString] = srcNamespaces
				}
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			sources := []*model.Source{}
			for srcType, namespaces := range srcTypes {
				sourceNamespaces := []*model.SourceNamespace{}
				for namespace, sourceNames := range namespaces {
					srcNamespace := &model.SourceNamespace{
						Namespace: namespace,
						Names:     sourceNames,
					}
					sourceNamespaces = append(sourceNamespaces, srcNamespace)
				}

				source := &model.Source{
					Type:       srcType,
					Namespaces: sourceNamespaces,
				}
				sources = append(sources, source)
			}

			return sources, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Source), nil
}

func (c *neo4jClient) sourcesType(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}
	sb.WriteString("MATCH (root:Src)-[:SrcHasType]->(type:SrcType)")

	if sourceSpec.Type != nil {

		matchProperties(&sb, firstMatch, "type", "type", "$srcType")
		queryValues["srcType"] = sourceSpec.Type
	}

	sb.WriteString(" RETURN type.type")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			sources := []*model.Source{}
			for result.Next() {

				source := &model.Source{
					Type:       result.Record().Values[0].(string),
					Namespaces: []*model.SourceNamespace{},
				}

				sources = append(sources, source)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return sources, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Source), nil
}

func (c *neo4jClient) sourcesNamespace(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}
	sb.WriteString("MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)")

	if sourceSpec.Type != nil {

		matchProperties(&sb, firstMatch, "type", "type", "$srcType")
		firstMatch = false
		queryValues["srcType"] = sourceSpec.Type
	}
	if sourceSpec.Namespace != nil {

		matchProperties(&sb, firstMatch, "namespace", "namespace", "$srcNamespace")
		queryValues["srcNamespace"] = sourceSpec.Namespace
	}
	sb.WriteString(" RETURN type.type, namespace.namespace")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			srcTypes := map[string][]*model.SourceNamespace{}
			for result.Next() {

				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				srcNamespace := &model.SourceNamespace{
					Namespace: namespaceString,
					Names:     []*model.SourceName{},
				}
				srcTypes[typeString] = append(srcTypes[typeString], srcNamespace)

			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			sources := []*model.Source{}
			for srcType, namespaces := range srcTypes {
				source := &model.Source{
					Type:       srcType,
					Namespaces: namespaces,
				}
				sources = append(sources, source)
			}

			return sources, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Source), nil
}

func (c *neo4jClient) IngestSource(ctx context.Context, source *model.SourceInputSpec) (*model.Source, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	values := map[string]any{}
	values["sourceType"] = source.Type
	values["namespace"] = source.Namespace
	values["name"] = source.Name

	if source.Commit != nil && source.Tag != nil {
		if *source.Commit != "" && *source.Tag != "" {
			return nil, gqlerror.Errorf("Passing both commit and tag selectors is an error")
		}
	}

	if source.Commit != nil {
		values["commit"] = *source.Commit
	}

	if source.Tag != nil {
		values["tag"] = *source.Tag
	}

	result, err := session.WriteTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			query := `MERGE (root:Src)
MERGE (root) -[:SrcHasType]-> (type:SrcType{type:$sourceType})
MERGE (type) -[:SrcHasNamespace]-> (ns:SrcNamespace{namespace:$namespace})
MERGE (ns) -[:SrcHasName]-> (name:SrcName{name:$name,commit:$commit,tag:$tag})
RETURN type.type, ns.namespace, name.name, name.commit, name.tag`
			result, err := tx.Run(query, values)
			if err != nil {
				return nil, err
			}

			// query returns a single record
			record, err := result.Single()
			if err != nil {
				return nil, err
			}

			// TODO(mihaimaruseac): Extract this to a utility since it is repeated
			tag := (*string)(nil)
			if record.Values[4] != nil {
				// make sure to take a copy
				tagStr := record.Values[4].(string)
				tag = &tagStr
			}
			commit := (*string)(nil)
			if record.Values[3] != nil {
				// make sure to take a copy
				commitStr := record.Values[3].(string)
				commit = &commitStr
			}
			nameStr := record.Values[2].(string)
			name := &model.SourceName{
				Name:   nameStr,
				Tag:    tag,
				Commit: commit,
			}

			namespaceStr := record.Values[1].(string)
			namespace := &model.SourceNamespace{
				Namespace: namespaceStr,
				Names:     []*model.SourceName{name},
			}

			srcType := record.Values[0].(string)
			src := model.Source{
				Type:       srcType,
				Namespaces: []*model.SourceNamespace{namespace},
			}

			return &src, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.Source), nil
}

func setSrcMatchValues(sb *strings.Builder, src *model.SourceSpec, objectSrc bool, firstMatch *bool, queryValues map[string]any) {
	if src != nil {
		if src.Type != nil {
			if !objectSrc {
				matchProperties(sb, *firstMatch, "type", "type", "$srcType")
				queryValues["srcType"] = src.Type
			} else {
				matchProperties(sb, *firstMatch, "objSrcType", "type", "$objSrcType")
				queryValues["objSrcType"] = src.Type
			}
			*firstMatch = false
		}
		if src.Namespace != nil {
			if !objectSrc {
				matchProperties(sb, *firstMatch, "namespace", "namespace", "$srcNamespace")
				queryValues["srcNamespace"] = src.Namespace
			} else {
				matchProperties(sb, *firstMatch, "objSrcNamespace", "namespace", "$objSrcNamespace")
				queryValues["objSrcNamespace"] = src.Namespace
			}
			*firstMatch = false
		}
		if src.Name != nil {
			if !objectSrc {
				matchProperties(sb, *firstMatch, "name", "name", "$srcName")
				queryValues["srcName"] = src.Name
			} else {
				matchProperties(sb, *firstMatch, "objSrcName", "name", "$objSrcName")
				queryValues["objSrcName"] = src.Name
			}
			*firstMatch = false
		}

		if src.Tag != nil {
			if !objectSrc {
				matchProperties(sb, *firstMatch, "name", "tag", "$srcTag")
				queryValues["srcTag"] = src.Tag
			} else {
				matchProperties(sb, *firstMatch, "objSrcName", "tag", "$objSrcTag")
				queryValues["objSrcTag"] = src.Tag
			}
			*firstMatch = false
		}

		if src.Commit != nil {
			if !objectSrc {
				matchProperties(sb, *firstMatch, "name", "commit", "$srcCommit")
				queryValues["srcCommit"] = src.Commit
			} else {
				matchProperties(sb, *firstMatch, "objSrcName", "commit", "$objSrcCommit")
				queryValues["objSrcCommit"] = src.Commit
			}
			*firstMatch = false
		}
	}
}
