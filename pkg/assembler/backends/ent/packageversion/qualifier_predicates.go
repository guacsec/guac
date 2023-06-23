package packageversion

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// QualifiersIsEmpty filters out package versions that have no qualifiers.
// It accounts for null, empty array, and null literal json value.
func QualifiersIsEmpty() func(*sql.Selector) {
	return func(s *sql.Selector) {
		s.Where(sql.Or(
			sql.IsNull(FieldQualifiers),
			sqljson.ValueIsNull(FieldQualifiers),
			sqljson.LenEQ(FieldQualifiers, 0),
		))
	}
}

type qualifier struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// QualifiersWithKeys filters out package versions that do not have the given qualifier keys.
func QualifiersWithKeys(key string, keys ...string) func(*sql.Selector) {
	queryStruct := []qualifier{{Key: key}}
	for _, k := range keys {
		queryStruct = append(queryStruct, qualifier{Key: k})
	}

	return func(s *sql.Selector) {
		s.Where(sqljson.ValueContains(FieldQualifiers, queryStruct))
	}
}

// QualifiersContains filters out package versions that do not have the given qualifier key/value pair.
func QualifiersContains(key, value string) func(*sql.Selector) {
	queryStruct := []qualifier{{Key: key, Value: value}}

	return func(s *sql.Selector) {
		s.Where(sqljson.ValueContains(FieldQualifiers, queryStruct))
	}
}

// QualifiersMatchSpec constructs a JSON field query for the given qualifiers.
// If the value is nil, it will query for the key only.
// If the value is not nil, it will query for the key/value pair.
// Each additional spec will be ANDed together.
func QualifiersMatchSpec(spec []*model.PackageQualifierSpec) func(*sql.Selector) {
	return func(s *sql.Selector) {
		if len(spec) == 0 {
			return
		}

		for _, q := range spec {
			if q.Value == nil {
				QualifiersWithKeys(q.Key)(s)
			} else {
				QualifiersContains(q.Key, *q.Value)(s)
			}
		}
	}
}
