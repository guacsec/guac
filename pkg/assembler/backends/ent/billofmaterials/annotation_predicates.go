package billofmaterials

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// AnnotationsIsEmpty filters out package versions that have no Annotations.
// It accounts for null, empty array, and null literal json value.
func AnnotationsIsEmpty() func(*sql.Selector) {
	return func(s *sql.Selector) {
		s.Where(sql.Or(
			sql.IsNull(FieldAnnotations),
			sqljson.ValueIsNull(FieldAnnotations),
			sqljson.LenEQ(FieldAnnotations, 0),
		))
	}
}

type annotation struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// AnnotationsWithKeys filters out package versions that do not have the given qualifier keys.
func AnnotationsWithKeys(key string, keys ...string) func(*sql.Selector) {
	queryStruct := []annotation{{Key: key}}
	for _, k := range keys {
		queryStruct = append(queryStruct, annotation{Key: k})
	}

	return func(s *sql.Selector) {
		s.Where(sqljson.ValueContains(FieldAnnotations, queryStruct))
	}
}

// AnnotationsContains filters out package versions that do not have the given qualifier key/value pair.
func AnnotationsContains(key, value string) func(*sql.Selector) {
	queryStruct := []annotation{{Key: key, Value: value}}

	return func(s *sql.Selector) {
		s.Where(sqljson.ValueContains(FieldAnnotations, queryStruct))
	}
}

// AnnotationsMatchSpec constructs a JSON field query for the given Annotations.
// If the value is nil, it will query for the key only.
// If the value is not nil, it will query for the key/value pair.
// Each additional spec will be ANDed together.
func AnnotationsMatchSpec(spec []*model.AnnotationSpec) func(*sql.Selector) {
	return func(s *sql.Selector) {
		if len(spec) == 0 {
			return
		}

		for _, q := range spec {
			AnnotationsContains(q.Key, q.Value)(s)
		}
	}
}
