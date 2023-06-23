package packageversion

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
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

func QualifiersWithKeys(key string, keys ...string) func(*sql.Selector) {
	queryStruct := []qualifier{{Key: key}}
	for _, k := range keys {
		queryStruct = append(queryStruct, qualifier{Key: k})
	}

	return func(s *sql.Selector) {
		s.Where(sqljson.ValueContains(FieldQualifiers, queryStruct))
	}
}

func QualifiersContains(key, value string) func(*sql.Selector) {
	queryStruct := []qualifier{{Key: key, Value: value}}

	return func(s *sql.Selector) {
		s.Where(sqljson.ValueContains(FieldQualifiers, queryStruct))
	}
}
