// Code generated by ent, DO NOT EDIT.

package hook

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
)

// The ArtifactFunc type is an adapter to allow the use of ordinary
// function as Artifact mutator.
type ArtifactFunc func(context.Context, *ent.ArtifactMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f ArtifactFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.ArtifactMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.ArtifactMutation", m)
}

// The BillOfMaterialsFunc type is an adapter to allow the use of ordinary
// function as BillOfMaterials mutator.
type BillOfMaterialsFunc func(context.Context, *ent.BillOfMaterialsMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f BillOfMaterialsFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.BillOfMaterialsMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.BillOfMaterialsMutation", m)
}

// The BuilderFunc type is an adapter to allow the use of ordinary
// function as Builder mutator.
type BuilderFunc func(context.Context, *ent.BuilderMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f BuilderFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.BuilderMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.BuilderMutation", m)
}

// The CertificationFunc type is an adapter to allow the use of ordinary
// function as Certification mutator.
type CertificationFunc func(context.Context, *ent.CertificationMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f CertificationFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.CertificationMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.CertificationMutation", m)
}

// The CertifyScorecardFunc type is an adapter to allow the use of ordinary
// function as CertifyScorecard mutator.
type CertifyScorecardFunc func(context.Context, *ent.CertifyScorecardMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f CertifyScorecardFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.CertifyScorecardMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.CertifyScorecardMutation", m)
}

// The CertifyVulnFunc type is an adapter to allow the use of ordinary
// function as CertifyVuln mutator.
type CertifyVulnFunc func(context.Context, *ent.CertifyVulnMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f CertifyVulnFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.CertifyVulnMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.CertifyVulnMutation", m)
}

// The DependencyFunc type is an adapter to allow the use of ordinary
// function as Dependency mutator.
type DependencyFunc func(context.Context, *ent.DependencyMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f DependencyFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.DependencyMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.DependencyMutation", m)
}

// The HasSourceAtFunc type is an adapter to allow the use of ordinary
// function as HasSourceAt mutator.
type HasSourceAtFunc func(context.Context, *ent.HasSourceAtMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f HasSourceAtFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.HasSourceAtMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.HasSourceAtMutation", m)
}

// The HashEqualFunc type is an adapter to allow the use of ordinary
// function as HashEqual mutator.
type HashEqualFunc func(context.Context, *ent.HashEqualMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f HashEqualFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.HashEqualMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.HashEqualMutation", m)
}

// The IsVulnerabilityFunc type is an adapter to allow the use of ordinary
// function as IsVulnerability mutator.
type IsVulnerabilityFunc func(context.Context, *ent.IsVulnerabilityMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f IsVulnerabilityFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.IsVulnerabilityMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.IsVulnerabilityMutation", m)
}

// The OccurrenceFunc type is an adapter to allow the use of ordinary
// function as Occurrence mutator.
type OccurrenceFunc func(context.Context, *ent.OccurrenceMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f OccurrenceFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.OccurrenceMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.OccurrenceMutation", m)
}

// The PackageNameFunc type is an adapter to allow the use of ordinary
// function as PackageName mutator.
type PackageNameFunc func(context.Context, *ent.PackageNameMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f PackageNameFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.PackageNameMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.PackageNameMutation", m)
}

// The PackageNamespaceFunc type is an adapter to allow the use of ordinary
// function as PackageNamespace mutator.
type PackageNamespaceFunc func(context.Context, *ent.PackageNamespaceMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f PackageNamespaceFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.PackageNamespaceMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.PackageNamespaceMutation", m)
}

// The PackageTypeFunc type is an adapter to allow the use of ordinary
// function as PackageType mutator.
type PackageTypeFunc func(context.Context, *ent.PackageTypeMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f PackageTypeFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.PackageTypeMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.PackageTypeMutation", m)
}

// The PackageVersionFunc type is an adapter to allow the use of ordinary
// function as PackageVersion mutator.
type PackageVersionFunc func(context.Context, *ent.PackageVersionMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f PackageVersionFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.PackageVersionMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.PackageVersionMutation", m)
}

// The PkgEqualFunc type is an adapter to allow the use of ordinary
// function as PkgEqual mutator.
type PkgEqualFunc func(context.Context, *ent.PkgEqualMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f PkgEqualFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.PkgEqualMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.PkgEqualMutation", m)
}

// The SLSAAttestationFunc type is an adapter to allow the use of ordinary
// function as SLSAAttestation mutator.
type SLSAAttestationFunc func(context.Context, *ent.SLSAAttestationMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SLSAAttestationFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SLSAAttestationMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SLSAAttestationMutation", m)
}

// The ScorecardFunc type is an adapter to allow the use of ordinary
// function as Scorecard mutator.
type ScorecardFunc func(context.Context, *ent.ScorecardMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f ScorecardFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.ScorecardMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.ScorecardMutation", m)
}

// The SecurityAdvisoryFunc type is an adapter to allow the use of ordinary
// function as SecurityAdvisory mutator.
type SecurityAdvisoryFunc func(context.Context, *ent.SecurityAdvisoryMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SecurityAdvisoryFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SecurityAdvisoryMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SecurityAdvisoryMutation", m)
}

// The SourceNameFunc type is an adapter to allow the use of ordinary
// function as SourceName mutator.
type SourceNameFunc func(context.Context, *ent.SourceNameMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SourceNameFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SourceNameMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SourceNameMutation", m)
}

// The SourceNamespaceFunc type is an adapter to allow the use of ordinary
// function as SourceNamespace mutator.
type SourceNamespaceFunc func(context.Context, *ent.SourceNamespaceMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SourceNamespaceFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SourceNamespaceMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SourceNamespaceMutation", m)
}

// The SourceTypeFunc type is an adapter to allow the use of ordinary
// function as SourceType mutator.
type SourceTypeFunc func(context.Context, *ent.SourceTypeMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SourceTypeFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SourceTypeMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SourceTypeMutation", m)
}

// Condition is a hook condition function.
type Condition func(context.Context, ent.Mutation) bool

// And groups conditions with the AND operator.
func And(first, second Condition, rest ...Condition) Condition {
	return func(ctx context.Context, m ent.Mutation) bool {
		if !first(ctx, m) || !second(ctx, m) {
			return false
		}
		for _, cond := range rest {
			if !cond(ctx, m) {
				return false
			}
		}
		return true
	}
}

// Or groups conditions with the OR operator.
func Or(first, second Condition, rest ...Condition) Condition {
	return func(ctx context.Context, m ent.Mutation) bool {
		if first(ctx, m) || second(ctx, m) {
			return true
		}
		for _, cond := range rest {
			if cond(ctx, m) {
				return true
			}
		}
		return false
	}
}

// Not negates a given condition.
func Not(cond Condition) Condition {
	return func(ctx context.Context, m ent.Mutation) bool {
		return !cond(ctx, m)
	}
}

// HasOp is a condition testing mutation operation.
func HasOp(op ent.Op) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		return m.Op().Is(op)
	}
}

// HasAddedFields is a condition validating `.AddedField` on fields.
func HasAddedFields(field string, fields ...string) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		if _, exists := m.AddedField(field); !exists {
			return false
		}
		for _, field := range fields {
			if _, exists := m.AddedField(field); !exists {
				return false
			}
		}
		return true
	}
}

// HasClearedFields is a condition validating `.FieldCleared` on fields.
func HasClearedFields(field string, fields ...string) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		if exists := m.FieldCleared(field); !exists {
			return false
		}
		for _, field := range fields {
			if exists := m.FieldCleared(field); !exists {
				return false
			}
		}
		return true
	}
}

// HasFields is a condition validating `.Field` on fields.
func HasFields(field string, fields ...string) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		if _, exists := m.Field(field); !exists {
			return false
		}
		for _, field := range fields {
			if _, exists := m.Field(field); !exists {
				return false
			}
		}
		return true
	}
}

// If executes the given hook under condition.
//
//	hook.If(ComputeAverage, And(HasFields(...), HasAddedFields(...)))
func If(hk ent.Hook, cond Condition) ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if cond(ctx, m) {
				return hk(next).Mutate(ctx, m)
			}
			return next.Mutate(ctx, m)
		})
	}
}

// On executes the given hook only for the given operation.
//
//	hook.On(Log, ent.Delete|ent.Create)
func On(hk ent.Hook, op ent.Op) ent.Hook {
	return If(hk, HasOp(op))
}

// Unless skips the given hook only for the given operation.
//
//	hook.Unless(Log, ent.Update|ent.UpdateOne)
func Unless(hk ent.Hook, op ent.Op) ent.Hook {
	return If(hk, Not(HasOp(op)))
}

// FixedError is a hook returning a fixed error.
func FixedError(err error) ent.Hook {
	return func(ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(context.Context, ent.Mutation) (ent.Value, error) {
			return nil, err
		})
	}
}

// Reject returns a hook that rejects all operations that match op.
//
//	func (T) Hooks() []ent.Hook {
//		return []ent.Hook{
//			Reject(ent.Delete|ent.Update),
//		}
//	}
func Reject(op ent.Op) ent.Hook {
	hk := FixedError(fmt.Errorf("%s operation is not allowed", op))
	return On(hk, op)
}

// Chain acts as a list of hooks and is effectively immutable.
// Once created, it will always hold the same set of hooks in the same order.
type Chain struct {
	hooks []ent.Hook
}

// NewChain creates a new chain of hooks.
func NewChain(hooks ...ent.Hook) Chain {
	return Chain{append([]ent.Hook(nil), hooks...)}
}

// Hook chains the list of hooks and returns the final hook.
func (c Chain) Hook() ent.Hook {
	return func(mutator ent.Mutator) ent.Mutator {
		for i := len(c.hooks) - 1; i >= 0; i-- {
			mutator = c.hooks[i](mutator)
		}
		return mutator
	}
}

// Append extends a chain, adding the specified hook
// as the last ones in the mutation flow.
func (c Chain) Append(hooks ...ent.Hook) Chain {
	newHooks := make([]ent.Hook, 0, len(c.hooks)+len(hooks))
	newHooks = append(newHooks, c.hooks...)
	newHooks = append(newHooks, hooks...)
	return Chain{newHooks}
}

// Extend extends a chain, adding the specified chain
// as the last ones in the mutation flow.
func (c Chain) Extend(chain Chain) Chain {
	return c.Append(chain.hooks...)
}
