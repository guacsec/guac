// Code generated by ent, DO NOT EDIT.

package hashequal

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id uuid.UUID) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id uuid.UUID) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id uuid.UUID) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...uuid.UUID) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...uuid.UUID) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id uuid.UUID) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id uuid.UUID) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id uuid.UUID) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id uuid.UUID) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLTE(FieldID, id))
}

// Origin applies equality check predicate on the "origin" field. It's identical to OriginEQ.
func Origin(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldOrigin, v))
}

// Collector applies equality check predicate on the "collector" field. It's identical to CollectorEQ.
func Collector(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldCollector, v))
}

// Justification applies equality check predicate on the "justification" field. It's identical to JustificationEQ.
func Justification(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldJustification, v))
}

// ArtifactsHash applies equality check predicate on the "artifacts_hash" field. It's identical to ArtifactsHashEQ.
func ArtifactsHash(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldArtifactsHash, v))
}

// OriginEQ applies the EQ predicate on the "origin" field.
func OriginEQ(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldOrigin, v))
}

// OriginNEQ applies the NEQ predicate on the "origin" field.
func OriginNEQ(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNEQ(FieldOrigin, v))
}

// OriginIn applies the In predicate on the "origin" field.
func OriginIn(vs ...string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldIn(FieldOrigin, vs...))
}

// OriginNotIn applies the NotIn predicate on the "origin" field.
func OriginNotIn(vs ...string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNotIn(FieldOrigin, vs...))
}

// OriginGT applies the GT predicate on the "origin" field.
func OriginGT(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGT(FieldOrigin, v))
}

// OriginGTE applies the GTE predicate on the "origin" field.
func OriginGTE(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGTE(FieldOrigin, v))
}

// OriginLT applies the LT predicate on the "origin" field.
func OriginLT(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLT(FieldOrigin, v))
}

// OriginLTE applies the LTE predicate on the "origin" field.
func OriginLTE(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLTE(FieldOrigin, v))
}

// OriginContains applies the Contains predicate on the "origin" field.
func OriginContains(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldContains(FieldOrigin, v))
}

// OriginHasPrefix applies the HasPrefix predicate on the "origin" field.
func OriginHasPrefix(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldHasPrefix(FieldOrigin, v))
}

// OriginHasSuffix applies the HasSuffix predicate on the "origin" field.
func OriginHasSuffix(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldHasSuffix(FieldOrigin, v))
}

// OriginEqualFold applies the EqualFold predicate on the "origin" field.
func OriginEqualFold(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEqualFold(FieldOrigin, v))
}

// OriginContainsFold applies the ContainsFold predicate on the "origin" field.
func OriginContainsFold(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldContainsFold(FieldOrigin, v))
}

// CollectorEQ applies the EQ predicate on the "collector" field.
func CollectorEQ(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldCollector, v))
}

// CollectorNEQ applies the NEQ predicate on the "collector" field.
func CollectorNEQ(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNEQ(FieldCollector, v))
}

// CollectorIn applies the In predicate on the "collector" field.
func CollectorIn(vs ...string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldIn(FieldCollector, vs...))
}

// CollectorNotIn applies the NotIn predicate on the "collector" field.
func CollectorNotIn(vs ...string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNotIn(FieldCollector, vs...))
}

// CollectorGT applies the GT predicate on the "collector" field.
func CollectorGT(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGT(FieldCollector, v))
}

// CollectorGTE applies the GTE predicate on the "collector" field.
func CollectorGTE(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGTE(FieldCollector, v))
}

// CollectorLT applies the LT predicate on the "collector" field.
func CollectorLT(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLT(FieldCollector, v))
}

// CollectorLTE applies the LTE predicate on the "collector" field.
func CollectorLTE(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLTE(FieldCollector, v))
}

// CollectorContains applies the Contains predicate on the "collector" field.
func CollectorContains(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldContains(FieldCollector, v))
}

// CollectorHasPrefix applies the HasPrefix predicate on the "collector" field.
func CollectorHasPrefix(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldHasPrefix(FieldCollector, v))
}

// CollectorHasSuffix applies the HasSuffix predicate on the "collector" field.
func CollectorHasSuffix(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldHasSuffix(FieldCollector, v))
}

// CollectorEqualFold applies the EqualFold predicate on the "collector" field.
func CollectorEqualFold(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEqualFold(FieldCollector, v))
}

// CollectorContainsFold applies the ContainsFold predicate on the "collector" field.
func CollectorContainsFold(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldContainsFold(FieldCollector, v))
}

// JustificationEQ applies the EQ predicate on the "justification" field.
func JustificationEQ(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldJustification, v))
}

// JustificationNEQ applies the NEQ predicate on the "justification" field.
func JustificationNEQ(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNEQ(FieldJustification, v))
}

// JustificationIn applies the In predicate on the "justification" field.
func JustificationIn(vs ...string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldIn(FieldJustification, vs...))
}

// JustificationNotIn applies the NotIn predicate on the "justification" field.
func JustificationNotIn(vs ...string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNotIn(FieldJustification, vs...))
}

// JustificationGT applies the GT predicate on the "justification" field.
func JustificationGT(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGT(FieldJustification, v))
}

// JustificationGTE applies the GTE predicate on the "justification" field.
func JustificationGTE(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGTE(FieldJustification, v))
}

// JustificationLT applies the LT predicate on the "justification" field.
func JustificationLT(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLT(FieldJustification, v))
}

// JustificationLTE applies the LTE predicate on the "justification" field.
func JustificationLTE(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLTE(FieldJustification, v))
}

// JustificationContains applies the Contains predicate on the "justification" field.
func JustificationContains(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldContains(FieldJustification, v))
}

// JustificationHasPrefix applies the HasPrefix predicate on the "justification" field.
func JustificationHasPrefix(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldHasPrefix(FieldJustification, v))
}

// JustificationHasSuffix applies the HasSuffix predicate on the "justification" field.
func JustificationHasSuffix(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldHasSuffix(FieldJustification, v))
}

// JustificationEqualFold applies the EqualFold predicate on the "justification" field.
func JustificationEqualFold(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEqualFold(FieldJustification, v))
}

// JustificationContainsFold applies the ContainsFold predicate on the "justification" field.
func JustificationContainsFold(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldContainsFold(FieldJustification, v))
}

// ArtifactsHashEQ applies the EQ predicate on the "artifacts_hash" field.
func ArtifactsHashEQ(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEQ(FieldArtifactsHash, v))
}

// ArtifactsHashNEQ applies the NEQ predicate on the "artifacts_hash" field.
func ArtifactsHashNEQ(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNEQ(FieldArtifactsHash, v))
}

// ArtifactsHashIn applies the In predicate on the "artifacts_hash" field.
func ArtifactsHashIn(vs ...string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldIn(FieldArtifactsHash, vs...))
}

// ArtifactsHashNotIn applies the NotIn predicate on the "artifacts_hash" field.
func ArtifactsHashNotIn(vs ...string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldNotIn(FieldArtifactsHash, vs...))
}

// ArtifactsHashGT applies the GT predicate on the "artifacts_hash" field.
func ArtifactsHashGT(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGT(FieldArtifactsHash, v))
}

// ArtifactsHashGTE applies the GTE predicate on the "artifacts_hash" field.
func ArtifactsHashGTE(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldGTE(FieldArtifactsHash, v))
}

// ArtifactsHashLT applies the LT predicate on the "artifacts_hash" field.
func ArtifactsHashLT(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLT(FieldArtifactsHash, v))
}

// ArtifactsHashLTE applies the LTE predicate on the "artifacts_hash" field.
func ArtifactsHashLTE(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldLTE(FieldArtifactsHash, v))
}

// ArtifactsHashContains applies the Contains predicate on the "artifacts_hash" field.
func ArtifactsHashContains(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldContains(FieldArtifactsHash, v))
}

// ArtifactsHashHasPrefix applies the HasPrefix predicate on the "artifacts_hash" field.
func ArtifactsHashHasPrefix(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldHasPrefix(FieldArtifactsHash, v))
}

// ArtifactsHashHasSuffix applies the HasSuffix predicate on the "artifacts_hash" field.
func ArtifactsHashHasSuffix(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldHasSuffix(FieldArtifactsHash, v))
}

// ArtifactsHashEqualFold applies the EqualFold predicate on the "artifacts_hash" field.
func ArtifactsHashEqualFold(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldEqualFold(FieldArtifactsHash, v))
}

// ArtifactsHashContainsFold applies the ContainsFold predicate on the "artifacts_hash" field.
func ArtifactsHashContainsFold(v string) predicate.HashEqual {
	return predicate.HashEqual(sql.FieldContainsFold(FieldArtifactsHash, v))
}

// HasArtifacts applies the HasEdge predicate on the "artifacts" edge.
func HasArtifacts() predicate.HashEqual {
	return predicate.HashEqual(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, ArtifactsTable, ArtifactsPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasArtifactsWith applies the HasEdge predicate on the "artifacts" edge with a given conditions (other predicates).
func HasArtifactsWith(preds ...predicate.Artifact) predicate.HashEqual {
	return predicate.HashEqual(func(s *sql.Selector) {
		step := newArtifactsStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.HashEqual) predicate.HashEqual {
	return predicate.HashEqual(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.HashEqual) predicate.HashEqual {
	return predicate.HashEqual(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.HashEqual) predicate.HashEqual {
	return predicate.HashEqual(sql.NotPredicates(p))
}
