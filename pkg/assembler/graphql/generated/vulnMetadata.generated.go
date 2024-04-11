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

func (ec *executionContext) _VulnerabilityMetadata_id(ctx context.Context, field graphql.CollectedField, obj *model.VulnerabilityMetadata) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_VulnerabilityMetadata_id(ctx, field)
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
	resTmp := ec._fieldMiddleware(ctx, obj, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.ID, nil
	})

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

func (ec *executionContext) fieldContext_VulnerabilityMetadata_id(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "VulnerabilityMetadata",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type ID does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _VulnerabilityMetadata_vulnerability(ctx context.Context, field graphql.CollectedField, obj *model.VulnerabilityMetadata) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_VulnerabilityMetadata_vulnerability(ctx, field)
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
	resTmp := ec._fieldMiddleware(ctx, obj, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Vulnerability, nil
	})

	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(*model.Vulnerability)
	fc.Result = res
	return ec.marshalNVulnerability2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerability(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_VulnerabilityMetadata_vulnerability(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "VulnerabilityMetadata",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			switch field.Name {
			case "id":
				return ec.fieldContext_Vulnerability_id(ctx, field)
			case "type":
				return ec.fieldContext_Vulnerability_type(ctx, field)
			case "vulnerabilityIDs":
				return ec.fieldContext_Vulnerability_vulnerabilityIDs(ctx, field)
			}
			return nil, fmt.Errorf("no field named %q was found under type Vulnerability", field.Name)
		},
	}
	return fc, nil
}

func (ec *executionContext) _VulnerabilityMetadata_scoreType(ctx context.Context, field graphql.CollectedField, obj *model.VulnerabilityMetadata) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_VulnerabilityMetadata_scoreType(ctx, field)
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
	resTmp := ec._fieldMiddleware(ctx, obj, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.ScoreType, nil
	})

	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(model.VulnerabilityScoreType)
	fc.Result = res
	return ec.marshalNVulnerabilityScoreType2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityScoreType(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_VulnerabilityMetadata_scoreType(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "VulnerabilityMetadata",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type VulnerabilityScoreType does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _VulnerabilityMetadata_scoreValue(ctx context.Context, field graphql.CollectedField, obj *model.VulnerabilityMetadata) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_VulnerabilityMetadata_scoreValue(ctx, field)
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
	resTmp := ec._fieldMiddleware(ctx, obj, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.ScoreValue, nil
	})

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

func (ec *executionContext) fieldContext_VulnerabilityMetadata_scoreValue(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "VulnerabilityMetadata",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type Float does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _VulnerabilityMetadata_timestamp(ctx context.Context, field graphql.CollectedField, obj *model.VulnerabilityMetadata) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_VulnerabilityMetadata_timestamp(ctx, field)
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
	resTmp := ec._fieldMiddleware(ctx, obj, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Timestamp, nil
	})

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

func (ec *executionContext) fieldContext_VulnerabilityMetadata_timestamp(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "VulnerabilityMetadata",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type Time does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _VulnerabilityMetadata_origin(ctx context.Context, field graphql.CollectedField, obj *model.VulnerabilityMetadata) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_VulnerabilityMetadata_origin(ctx, field)
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
	resTmp := ec._fieldMiddleware(ctx, obj, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Origin, nil
	})

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

func (ec *executionContext) fieldContext_VulnerabilityMetadata_origin(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "VulnerabilityMetadata",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _VulnerabilityMetadata_collector(ctx context.Context, field graphql.CollectedField, obj *model.VulnerabilityMetadata) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_VulnerabilityMetadata_collector(ctx, field)
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
	resTmp := ec._fieldMiddleware(ctx, obj, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Collector, nil
	})

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

func (ec *executionContext) fieldContext_VulnerabilityMetadata_collector(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "VulnerabilityMetadata",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _VulnerabilityMetadata_documentRef(ctx context.Context, field graphql.CollectedField, obj *model.VulnerabilityMetadata) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_VulnerabilityMetadata_documentRef(ctx, field)
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
	resTmp := ec._fieldMiddleware(ctx, obj, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.DocumentRef, nil
	})

	if resTmp == nil {
		return graphql.Null
	}
	res := resTmp.(*string)
	fc.Result = res
	return ec.marshalOString2ᚖstring(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_VulnerabilityMetadata_documentRef(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "VulnerabilityMetadata",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

// endregion **************************** field.gotpl *****************************

// region    **************************** input.gotpl *****************************

func (ec *executionContext) unmarshalInputVulnerabilityMetadataInputSpec(ctx context.Context, obj interface{}) (model.VulnerabilityMetadataInputSpec, error) {
	var it model.VulnerabilityMetadataInputSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"scoreType", "scoreValue", "timestamp", "origin", "collector", "documentRef"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "scoreType":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("scoreType"))
			data, err := ec.unmarshalNVulnerabilityScoreType2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityScoreType(ctx, v)
			if err != nil {
				return it, err
			}
			it.ScoreType = data
		case "scoreValue":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("scoreValue"))
			data, err := ec.unmarshalNFloat2float64(ctx, v)
			if err != nil {
				return it, err
			}
			it.ScoreValue = data
		case "timestamp":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("timestamp"))
			data, err := ec.unmarshalNTime2timeᚐTime(ctx, v)
			if err != nil {
				return it, err
			}
			it.Timestamp = data
		case "origin":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("origin"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Origin = data
		case "collector":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("collector"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Collector = data
		case "documentRef":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("documentRef"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.DocumentRef = data
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputVulnerabilityMetadataSpec(ctx context.Context, obj interface{}) (model.VulnerabilityMetadataSpec, error) {
	var it model.VulnerabilityMetadataSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"id", "vulnerability", "scoreType", "scoreValue", "comparator", "timestamp", "origin", "collector", "documentRef"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "id":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("id"))
			data, err := ec.unmarshalOID2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.ID = data
		case "vulnerability":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("vulnerability"))
			data, err := ec.unmarshalOVulnerabilitySpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilitySpec(ctx, v)
			if err != nil {
				return it, err
			}
			it.Vulnerability = data
		case "scoreType":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("scoreType"))
			data, err := ec.unmarshalOVulnerabilityScoreType2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityScoreType(ctx, v)
			if err != nil {
				return it, err
			}
			it.ScoreType = data
		case "scoreValue":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("scoreValue"))
			data, err := ec.unmarshalOFloat2ᚖfloat64(ctx, v)
			if err != nil {
				return it, err
			}
			it.ScoreValue = data
		case "comparator":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("comparator"))
			data, err := ec.unmarshalOComparator2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐComparator(ctx, v)
			if err != nil {
				return it, err
			}
			it.Comparator = data
		case "timestamp":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("timestamp"))
			data, err := ec.unmarshalOTime2ᚖtimeᚐTime(ctx, v)
			if err != nil {
				return it, err
			}
			it.Timestamp = data
		case "origin":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("origin"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Origin = data
		case "collector":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("collector"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Collector = data
		case "documentRef":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("documentRef"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.DocumentRef = data
		}
	}

	return it, nil
}

// endregion **************************** input.gotpl *****************************

// region    ************************** interface.gotpl ***************************

// endregion ************************** interface.gotpl ***************************

// region    **************************** object.gotpl ****************************

var vulnerabilityMetadataImplementors = []string{"VulnerabilityMetadata", "Node"}

func (ec *executionContext) _VulnerabilityMetadata(ctx context.Context, sel ast.SelectionSet, obj *model.VulnerabilityMetadata) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, vulnerabilityMetadataImplementors)

	out := graphql.NewFieldSet(fields)
	deferred := make(map[string]*graphql.FieldSet)
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("VulnerabilityMetadata")
		case "id":
			out.Values[i] = ec._VulnerabilityMetadata_id(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "vulnerability":
			out.Values[i] = ec._VulnerabilityMetadata_vulnerability(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "scoreType":
			out.Values[i] = ec._VulnerabilityMetadata_scoreType(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "scoreValue":
			out.Values[i] = ec._VulnerabilityMetadata_scoreValue(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "timestamp":
			out.Values[i] = ec._VulnerabilityMetadata_timestamp(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "origin":
			out.Values[i] = ec._VulnerabilityMetadata_origin(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "collector":
			out.Values[i] = ec._VulnerabilityMetadata_collector(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "documentRef":
			out.Values[i] = ec._VulnerabilityMetadata_documentRef(ctx, field, obj)
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

func (ec *executionContext) marshalNVulnerabilityMetadata2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityMetadataᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.VulnerabilityMetadata) graphql.Marshaler {
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
			ret[i] = ec.marshalNVulnerabilityMetadata2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityMetadata(ctx, sel, v[i])
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

func (ec *executionContext) marshalNVulnerabilityMetadata2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityMetadata(ctx context.Context, sel ast.SelectionSet, v *model.VulnerabilityMetadata) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._VulnerabilityMetadata(ctx, sel, v)
}

func (ec *executionContext) unmarshalNVulnerabilityMetadataInputSpec2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityMetadataInputSpec(ctx context.Context, v interface{}) (model.VulnerabilityMetadataInputSpec, error) {
	res, err := ec.unmarshalInputVulnerabilityMetadataInputSpec(ctx, v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNVulnerabilityMetadataInputSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityMetadataInputSpecᚄ(ctx context.Context, v interface{}) ([]*model.VulnerabilityMetadataInputSpec, error) {
	var vSlice []interface{}
	if v != nil {
		vSlice = graphql.CoerceList(v)
	}
	var err error
	res := make([]*model.VulnerabilityMetadataInputSpec, len(vSlice))
	for i := range vSlice {
		ctx := graphql.WithPathContext(ctx, graphql.NewPathWithIndex(i))
		res[i], err = ec.unmarshalNVulnerabilityMetadataInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityMetadataInputSpec(ctx, vSlice[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (ec *executionContext) unmarshalNVulnerabilityMetadataInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityMetadataInputSpec(ctx context.Context, v interface{}) (*model.VulnerabilityMetadataInputSpec, error) {
	res, err := ec.unmarshalInputVulnerabilityMetadataInputSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNVulnerabilityMetadataSpec2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityMetadataSpec(ctx context.Context, v interface{}) (model.VulnerabilityMetadataSpec, error) {
	res, err := ec.unmarshalInputVulnerabilityMetadataSpec(ctx, v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNVulnerabilityScoreType2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityScoreType(ctx context.Context, v interface{}) (model.VulnerabilityScoreType, error) {
	var res model.VulnerabilityScoreType
	err := res.UnmarshalGQL(v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) marshalNVulnerabilityScoreType2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityScoreType(ctx context.Context, sel ast.SelectionSet, v model.VulnerabilityScoreType) graphql.Marshaler {
	return v
}

func (ec *executionContext) unmarshalOComparator2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐComparator(ctx context.Context, v interface{}) (*model.Comparator, error) {
	if v == nil {
		return nil, nil
	}
	var res = new(model.Comparator)
	err := res.UnmarshalGQL(v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) marshalOComparator2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐComparator(ctx context.Context, sel ast.SelectionSet, v *model.Comparator) graphql.Marshaler {
	if v == nil {
		return graphql.Null
	}
	return v
}

func (ec *executionContext) unmarshalOVulnerabilityScoreType2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityScoreType(ctx context.Context, v interface{}) (*model.VulnerabilityScoreType, error) {
	if v == nil {
		return nil, nil
	}
	var res = new(model.VulnerabilityScoreType)
	err := res.UnmarshalGQL(v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) marshalOVulnerabilityScoreType2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐVulnerabilityScoreType(ctx context.Context, sel ast.SelectionSet, v *model.VulnerabilityScoreType) graphql.Marshaler {
	if v == nil {
		return graphql.Null
	}
	return v
}

// endregion ***************************** type.gotpl *****************************
