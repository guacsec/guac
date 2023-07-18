// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package generated

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/ast"
)

// region    ************************** generated!.gotpl **************************

// endregion ************************** generated!.gotpl **************************

// region    ***************************** args.gotpl *****************************

// endregion ***************************** args.gotpl *****************************

// region    ************************** directives.gotpl **************************

// endregion ************************** directives.gotpl **************************

// region    **************************** field.gotpl *****************************

func (ec *executionContext) _CertifyScorecard_id(ctx context.Context, field graphql.CollectedField, obj *model.CertifyScorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_CertifyScorecard_id(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.ID, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNID2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_CertifyScorecard_id(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "CertifyScorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type ID does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _CertifyScorecard_source(ctx context.Context, field graphql.CollectedField, obj *model.CertifyScorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_CertifyScorecard_source(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Source, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(*model.Source)
	fc.Result = res
	return ec.marshalNSource2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐSource(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_CertifyScorecard_source(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "CertifyScorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			switch field.Name {
			case "id":
				return ec.fieldContext_Source_id(ctx, field)
			case "type":
				return ec.fieldContext_Source_type(ctx, field)
			case "namespaces":
				return ec.fieldContext_Source_namespaces(ctx, field)
			}
			return nil, fmt.Errorf("no field named %q was found under type Source", field.Name)
		},
	}
	return fc, nil
}

func (ec *executionContext) _CertifyScorecard_scorecard(ctx context.Context, field graphql.CollectedField, obj *model.CertifyScorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_CertifyScorecard_scorecard(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Scorecard, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(*model.Scorecard)
	fc.Result = res
	return ec.marshalNScorecard2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecard(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_CertifyScorecard_scorecard(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "CertifyScorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			switch field.Name {
			case "checks":
				return ec.fieldContext_Scorecard_checks(ctx, field)
			case "aggregateScore":
				return ec.fieldContext_Scorecard_aggregateScore(ctx, field)
			case "timeScanned":
				return ec.fieldContext_Scorecard_timeScanned(ctx, field)
			case "scorecardVersion":
				return ec.fieldContext_Scorecard_scorecardVersion(ctx, field)
			case "scorecardCommit":
				return ec.fieldContext_Scorecard_scorecardCommit(ctx, field)
			case "origin":
				return ec.fieldContext_Scorecard_origin(ctx, field)
			case "collector":
				return ec.fieldContext_Scorecard_collector(ctx, field)
			}
			return nil, fmt.Errorf("no field named %q was found under type Scorecard", field.Name)
		},
	}
	return fc, nil
}

func (ec *executionContext) _Scorecard_checks(ctx context.Context, field graphql.CollectedField, obj *model.Scorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_Scorecard_checks(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Checks, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.([]*model.ScorecardCheck)
	fc.Result = res
	return ec.marshalNScorecardCheck2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckᚄ(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_Scorecard_checks(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "Scorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			switch field.Name {
			case "check":
				return ec.fieldContext_ScorecardCheck_check(ctx, field)
			case "score":
				return ec.fieldContext_ScorecardCheck_score(ctx, field)
			}
			return nil, fmt.Errorf("no field named %q was found under type ScorecardCheck", field.Name)
		},
	}
	return fc, nil
}

func (ec *executionContext) _Scorecard_aggregateScore(ctx context.Context, field graphql.CollectedField, obj *model.Scorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_Scorecard_aggregateScore(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.AggregateScore, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(float64)
	fc.Result = res
	return ec.marshalNFloat2float64(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_Scorecard_aggregateScore(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "Scorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type Float does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _Scorecard_timeScanned(ctx context.Context, field graphql.CollectedField, obj *model.Scorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_Scorecard_timeScanned(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.TimeScanned, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(time.Time)
	fc.Result = res
	return ec.marshalNTime2timeᚐTime(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_Scorecard_timeScanned(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "Scorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type Time does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _Scorecard_scorecardVersion(ctx context.Context, field graphql.CollectedField, obj *model.Scorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_Scorecard_scorecardVersion(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.ScorecardVersion, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNString2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_Scorecard_scorecardVersion(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "Scorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _Scorecard_scorecardCommit(ctx context.Context, field graphql.CollectedField, obj *model.Scorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_Scorecard_scorecardCommit(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.ScorecardCommit, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNString2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_Scorecard_scorecardCommit(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "Scorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _Scorecard_origin(ctx context.Context, field graphql.CollectedField, obj *model.Scorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_Scorecard_origin(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Origin, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNString2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_Scorecard_origin(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "Scorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _Scorecard_collector(ctx context.Context, field graphql.CollectedField, obj *model.Scorecard) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_Scorecard_collector(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Collector, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNString2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_Scorecard_collector(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "Scorecard",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _ScorecardCheck_check(ctx context.Context, field graphql.CollectedField, obj *model.ScorecardCheck) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_ScorecardCheck_check(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Check, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNString2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_ScorecardCheck_check(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "ScorecardCheck",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _ScorecardCheck_score(ctx context.Context, field graphql.CollectedField, obj *model.ScorecardCheck) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_ScorecardCheck_score(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Score, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(int)
	fc.Result = res
	return ec.marshalNInt2int(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_ScorecardCheck_score(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "ScorecardCheck",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type Int does not have child fields")
		},
	}
	return fc, nil
}

// endregion **************************** field.gotpl *****************************

// region    **************************** input.gotpl *****************************

func (ec *executionContext) unmarshalInputCertifyScorecardSpec(ctx context.Context, obj interface{}) (model.CertifyScorecardSpec, error) {
	var it model.CertifyScorecardSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	if _, present := asMap["checks"]; !present {
		asMap["checks"] = []interface{}{}
	}

	fieldsInOrder := [...]string{"id", "source", "timeScanned", "aggregateScore", "checks", "scorecardVersion", "scorecardCommit", "origin", "collector"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "id":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("id"))
			data, err := ec.unmarshalOID2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.ID = data
		case "source":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("source"))
			data, err := ec.unmarshalOSourceSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐSourceSpec(ctx, v)
			if err != nil {
				return it, err
			}
			it.Source = data
		case "timeScanned":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("timeScanned"))
			data, err := ec.unmarshalOTime2ᚖtimeᚐTime(ctx, v)
			if err != nil {
				return it, err
			}
			it.TimeScanned = data
		case "aggregateScore":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("aggregateScore"))
			data, err := ec.unmarshalOFloat2ᚖfloat64(ctx, v)
			if err != nil {
				return it, err
			}
			it.AggregateScore = data
		case "checks":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("checks"))
			data, err := ec.unmarshalOScorecardCheckSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckSpecᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.Checks = data
		case "scorecardVersion":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("scorecardVersion"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.ScorecardVersion = data
		case "scorecardCommit":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("scorecardCommit"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.ScorecardCommit = data
		case "origin":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("origin"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Origin = data
		case "collector":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("collector"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Collector = data
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputScorecardCheckInputSpec(ctx context.Context, obj interface{}) (model.ScorecardCheckInputSpec, error) {
	var it model.ScorecardCheckInputSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"check", "score"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "check":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("check"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Check = data
		case "score":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("score"))
			data, err := ec.unmarshalNInt2int(ctx, v)
			if err != nil {
				return it, err
			}
			it.Score = data
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputScorecardCheckSpec(ctx context.Context, obj interface{}) (model.ScorecardCheckSpec, error) {
	var it model.ScorecardCheckSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"check", "score"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "check":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("check"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Check = data
		case "score":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("score"))
			data, err := ec.unmarshalNInt2int(ctx, v)
			if err != nil {
				return it, err
			}
			it.Score = data
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputScorecardInputSpec(ctx context.Context, obj interface{}) (model.ScorecardInputSpec, error) {
	var it model.ScorecardInputSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"checks", "aggregateScore", "timeScanned", "scorecardVersion", "scorecardCommit", "origin", "collector"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "checks":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("checks"))
			data, err := ec.unmarshalNScorecardCheckInputSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckInputSpecᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.Checks = data
		case "aggregateScore":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("aggregateScore"))
			data, err := ec.unmarshalNFloat2float64(ctx, v)
			if err != nil {
				return it, err
			}
			it.AggregateScore = data
		case "timeScanned":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("timeScanned"))
			data, err := ec.unmarshalNTime2timeᚐTime(ctx, v)
			if err != nil {
				return it, err
			}
			it.TimeScanned = data
		case "scorecardVersion":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("scorecardVersion"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.ScorecardVersion = data
		case "scorecardCommit":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("scorecardCommit"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.ScorecardCommit = data
		case "origin":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("origin"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Origin = data
		case "collector":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("collector"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Collector = data
		}
	}

	return it, nil
}

// endregion **************************** input.gotpl *****************************

// region    ************************** interface.gotpl ***************************

// endregion ************************** interface.gotpl ***************************

// region    **************************** object.gotpl ****************************

var certifyScorecardImplementors = []string{"CertifyScorecard", "Node"}

func (ec *executionContext) _CertifyScorecard(ctx context.Context, sel ast.SelectionSet, obj *model.CertifyScorecard) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, certifyScorecardImplementors)

	out := graphql.NewFieldSet(fields)
	deferred := make(map[string]*graphql.FieldSet)
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("CertifyScorecard")
		case "id":
			out.Values[i] = ec._CertifyScorecard_id(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "source":
			out.Values[i] = ec._CertifyScorecard_source(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "scorecard":
			out.Values[i] = ec._CertifyScorecard_scorecard(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		default:
			panic("unknown field " + strconv.Quote(field.Name))
		}
	}
	out.Dispatch(ctx)
	if out.Invalids > 0 {
		return graphql.Null
	}

	atomic.AddInt32(&ec.deferred, int32(len(deferred)))

	for label, dfs := range deferred {
		ec.processDeferredGroup(graphql.DeferredGroup{
			Label:    label,
			Path:     graphql.GetPath(ctx),
			FieldSet: dfs,
			Context:  ctx,
		})
	}

	return out
}

var scorecardImplementors = []string{"Scorecard"}

func (ec *executionContext) _Scorecard(ctx context.Context, sel ast.SelectionSet, obj *model.Scorecard) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, scorecardImplementors)

	out := graphql.NewFieldSet(fields)
	deferred := make(map[string]*graphql.FieldSet)
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("Scorecard")
		case "checks":
			out.Values[i] = ec._Scorecard_checks(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "aggregateScore":
			out.Values[i] = ec._Scorecard_aggregateScore(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "timeScanned":
			out.Values[i] = ec._Scorecard_timeScanned(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "scorecardVersion":
			out.Values[i] = ec._Scorecard_scorecardVersion(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "scorecardCommit":
			out.Values[i] = ec._Scorecard_scorecardCommit(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "origin":
			out.Values[i] = ec._Scorecard_origin(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "collector":
			out.Values[i] = ec._Scorecard_collector(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		default:
			panic("unknown field " + strconv.Quote(field.Name))
		}
	}
	out.Dispatch(ctx)
	if out.Invalids > 0 {
		return graphql.Null
	}

	atomic.AddInt32(&ec.deferred, int32(len(deferred)))

	for label, dfs := range deferred {
		ec.processDeferredGroup(graphql.DeferredGroup{
			Label:    label,
			Path:     graphql.GetPath(ctx),
			FieldSet: dfs,
			Context:  ctx,
		})
	}

	return out
}

var scorecardCheckImplementors = []string{"ScorecardCheck"}

func (ec *executionContext) _ScorecardCheck(ctx context.Context, sel ast.SelectionSet, obj *model.ScorecardCheck) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, scorecardCheckImplementors)

	out := graphql.NewFieldSet(fields)
	deferred := make(map[string]*graphql.FieldSet)
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("ScorecardCheck")
		case "check":
			out.Values[i] = ec._ScorecardCheck_check(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "score":
			out.Values[i] = ec._ScorecardCheck_score(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		default:
			panic("unknown field " + strconv.Quote(field.Name))
		}
	}
	out.Dispatch(ctx)
	if out.Invalids > 0 {
		return graphql.Null
	}

	atomic.AddInt32(&ec.deferred, int32(len(deferred)))

	for label, dfs := range deferred {
		ec.processDeferredGroup(graphql.DeferredGroup{
			Label:    label,
			Path:     graphql.GetPath(ctx),
			FieldSet: dfs,
			Context:  ctx,
		})
	}

	return out
}

// endregion **************************** object.gotpl ****************************

// region    ***************************** type.gotpl *****************************

func (ec *executionContext) marshalNCertifyScorecard2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyScorecard(ctx context.Context, sel ast.SelectionSet, v model.CertifyScorecard) graphql.Marshaler {
	return ec._CertifyScorecard(ctx, sel, &v)
}

func (ec *executionContext) marshalNCertifyScorecard2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyScorecardᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.CertifyScorecard) graphql.Marshaler {
	ret := make(graphql.Array, len(v))
	var wg sync.WaitGroup
	isLen1 := len(v) == 1
	if !isLen1 {
		wg.Add(len(v))
	}
	for i := range v {
		i := i
		fc := &graphql.FieldContext{
			Index:  &i,
			Result: &v[i],
		}
		ctx := graphql.WithFieldContext(ctx, fc)
		f := func(i int) {
			defer func() {
				if r := recover(); r != nil {
					ec.Error(ctx, ec.Recover(ctx, r))
					ret = nil
				}
			}()
			if !isLen1 {
				defer wg.Done()
			}
			ret[i] = ec.marshalNCertifyScorecard2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyScorecard(ctx, sel, v[i])
		}
		if isLen1 {
			f(i)
		} else {
			go f(i)
		}

	}
	wg.Wait()

	for _, e := range ret {
		if e == graphql.Null {
			return graphql.Null
		}
	}

	return ret
}

func (ec *executionContext) marshalNCertifyScorecard2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyScorecard(ctx context.Context, sel ast.SelectionSet, v *model.CertifyScorecard) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._CertifyScorecard(ctx, sel, v)
}

func (ec *executionContext) marshalNScorecard2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecard(ctx context.Context, sel ast.SelectionSet, v *model.Scorecard) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._Scorecard(ctx, sel, v)
}

func (ec *executionContext) marshalNScorecardCheck2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.ScorecardCheck) graphql.Marshaler {
	ret := make(graphql.Array, len(v))
	var wg sync.WaitGroup
	isLen1 := len(v) == 1
	if !isLen1 {
		wg.Add(len(v))
	}
	for i := range v {
		i := i
		fc := &graphql.FieldContext{
			Index:  &i,
			Result: &v[i],
		}
		ctx := graphql.WithFieldContext(ctx, fc)
		f := func(i int) {
			defer func() {
				if r := recover(); r != nil {
					ec.Error(ctx, ec.Recover(ctx, r))
					ret = nil
				}
			}()
			if !isLen1 {
				defer wg.Done()
			}
			ret[i] = ec.marshalNScorecardCheck2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheck(ctx, sel, v[i])
		}
		if isLen1 {
			f(i)
		} else {
			go f(i)
		}

	}
	wg.Wait()

	for _, e := range ret {
		if e == graphql.Null {
			return graphql.Null
		}
	}

	return ret
}

func (ec *executionContext) marshalNScorecardCheck2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheck(ctx context.Context, sel ast.SelectionSet, v *model.ScorecardCheck) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._ScorecardCheck(ctx, sel, v)
}

func (ec *executionContext) unmarshalNScorecardCheckInputSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckInputSpecᚄ(ctx context.Context, v interface{}) ([]*model.ScorecardCheckInputSpec, error) {
	var vSlice []interface{}
	if v != nil {
		vSlice = graphql.CoerceList(v)
	}
	var err error
	res := make([]*model.ScorecardCheckInputSpec, len(vSlice))
	for i := range vSlice {
		ctx := graphql.WithPathContext(ctx, graphql.NewPathWithIndex(i))
		res[i], err = ec.unmarshalNScorecardCheckInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckInputSpec(ctx, vSlice[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (ec *executionContext) unmarshalNScorecardCheckInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckInputSpec(ctx context.Context, v interface{}) (*model.ScorecardCheckInputSpec, error) {
	res, err := ec.unmarshalInputScorecardCheckInputSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNScorecardCheckSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckSpec(ctx context.Context, v interface{}) (*model.ScorecardCheckSpec, error) {
	res, err := ec.unmarshalInputScorecardCheckSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNScorecardInputSpec2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardInputSpec(ctx context.Context, v interface{}) (model.ScorecardInputSpec, error) {
	res, err := ec.unmarshalInputScorecardInputSpec(ctx, v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNScorecardInputSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardInputSpecᚄ(ctx context.Context, v interface{}) ([]*model.ScorecardInputSpec, error) {
	var vSlice []interface{}
	if v != nil {
		vSlice = graphql.CoerceList(v)
	}
	var err error
	res := make([]*model.ScorecardInputSpec, len(vSlice))
	for i := range vSlice {
		ctx := graphql.WithPathContext(ctx, graphql.NewPathWithIndex(i))
		res[i], err = ec.unmarshalNScorecardInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardInputSpec(ctx, vSlice[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (ec *executionContext) unmarshalNScorecardInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardInputSpec(ctx context.Context, v interface{}) (*model.ScorecardInputSpec, error) {
	res, err := ec.unmarshalInputScorecardInputSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNTime2timeᚐTime(ctx context.Context, v interface{}) (time.Time, error) {
	res, err := graphql.UnmarshalTime(v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) marshalNTime2timeᚐTime(ctx context.Context, sel ast.SelectionSet, v time.Time) graphql.Marshaler {
	res := graphql.MarshalTime(v)
	if res == graphql.Null {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
	}
	return res
}

func (ec *executionContext) unmarshalOCertifyScorecardSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyScorecardSpec(ctx context.Context, v interface{}) (*model.CertifyScorecardSpec, error) {
	if v == nil {
		return nil, nil
	}
	res, err := ec.unmarshalInputCertifyScorecardSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalOScorecardCheckSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckSpecᚄ(ctx context.Context, v interface{}) ([]*model.ScorecardCheckSpec, error) {
	if v == nil {
		return nil, nil
	}
	var vSlice []interface{}
	if v != nil {
		vSlice = graphql.CoerceList(v)
	}
	var err error
	res := make([]*model.ScorecardCheckSpec, len(vSlice))
	for i := range vSlice {
		ctx := graphql.WithPathContext(ctx, graphql.NewPathWithIndex(i))
		res[i], err = ec.unmarshalNScorecardCheckSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐScorecardCheckSpec(ctx, vSlice[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (ec *executionContext) unmarshalOTime2ᚖtimeᚐTime(ctx context.Context, v interface{}) (*time.Time, error) {
	if v == nil {
		return nil, nil
	}
	res, err := graphql.UnmarshalTime(v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) marshalOTime2ᚖtimeᚐTime(ctx context.Context, sel ast.SelectionSet, v *time.Time) graphql.Marshaler {
	if v == nil {
		return graphql.Null
	}
	res := graphql.MarshalTime(*v)
	return res
}

// endregion ***************************** type.gotpl *****************************
