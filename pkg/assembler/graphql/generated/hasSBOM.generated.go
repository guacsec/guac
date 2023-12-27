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

func (ec *executionContext) _HasSBOM_id(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_id(ctx, field)
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

func (ec *executionContext) fieldContext_HasSBOM_id(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type ID does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_subject(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_subject(ctx, field)
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
		return obj.Subject, nil
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
	res := resTmp.(model.PackageOrArtifact)
	fc.Result = res
	return ec.marshalNPackageOrArtifact2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPackageOrArtifact(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HasSBOM_subject(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type PackageOrArtifact does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_uri(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_uri(ctx, field)
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
		return obj.URI, nil
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

func (ec *executionContext) fieldContext_HasSBOM_uri(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_algorithm(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_algorithm(ctx, field)
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
		return obj.Algorithm, nil
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

func (ec *executionContext) fieldContext_HasSBOM_algorithm(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_digest(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_digest(ctx, field)
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
		return obj.Digest, nil
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

func (ec *executionContext) fieldContext_HasSBOM_digest(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_downloadLocation(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_downloadLocation(ctx, field)
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
		return obj.DownloadLocation, nil
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

func (ec *executionContext) fieldContext_HasSBOM_downloadLocation(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_origin(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_origin(ctx, field)
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

func (ec *executionContext) fieldContext_HasSBOM_origin(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_collector(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_collector(ctx, field)
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

func (ec *executionContext) fieldContext_HasSBOM_collector(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_knownSince(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_knownSince(ctx, field)
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
		return obj.KnownSince, nil
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

func (ec *executionContext) fieldContext_HasSBOM_knownSince(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type Time does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_includedSoftware(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_includedSoftware(ctx, field)
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
		return obj.IncludedSoftware, nil
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
	res := resTmp.([]model.PackageOrArtifact)
	fc.Result = res
	return ec.marshalNPackageOrArtifact2ᚕgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPackageOrArtifactᚄ(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HasSBOM_includedSoftware(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type PackageOrArtifact does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_includedDependencies(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_includedDependencies(ctx, field)
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
		return obj.IncludedDependencies, nil
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
	res := resTmp.([]*model.IsDependency)
	fc.Result = res
	return ec.marshalNIsDependency2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐIsDependencyᚄ(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HasSBOM_includedDependencies(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			switch field.Name {
			case "id":
				return ec.fieldContext_IsDependency_id(ctx, field)
			case "package":
				return ec.fieldContext_IsDependency_package(ctx, field)
			case "dependencyPackage":
				return ec.fieldContext_IsDependency_dependencyPackage(ctx, field)
			case "versionRange":
				return ec.fieldContext_IsDependency_versionRange(ctx, field)
			case "dependencyType":
				return ec.fieldContext_IsDependency_dependencyType(ctx, field)
			case "justification":
				return ec.fieldContext_IsDependency_justification(ctx, field)
			case "origin":
				return ec.fieldContext_IsDependency_origin(ctx, field)
			case "collector":
				return ec.fieldContext_IsDependency_collector(ctx, field)
			}
			return nil, fmt.Errorf("no field named %q was found under type IsDependency", field.Name)
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_includedOccurrences(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_includedOccurrences(ctx, field)
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
		return obj.IncludedOccurrences, nil
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
	res := resTmp.([]*model.IsOccurrence)
	fc.Result = res
	return ec.marshalNIsOccurrence2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐIsOccurrenceᚄ(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HasSBOM_includedOccurrences(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			switch field.Name {
			case "id":
				return ec.fieldContext_IsOccurrence_id(ctx, field)
			case "subject":
				return ec.fieldContext_IsOccurrence_subject(ctx, field)
			case "artifact":
				return ec.fieldContext_IsOccurrence_artifact(ctx, field)
			case "justification":
				return ec.fieldContext_IsOccurrence_justification(ctx, field)
			case "origin":
				return ec.fieldContext_IsOccurrence_origin(ctx, field)
			case "collector":
				return ec.fieldContext_IsOccurrence_collector(ctx, field)
			}
			return nil, fmt.Errorf("no field named %q was found under type IsOccurrence", field.Name)
		},
	}
	return fc, nil
}

// endregion **************************** field.gotpl *****************************

// region    **************************** input.gotpl *****************************

func (ec *executionContext) unmarshalInputHasSBOMIncludesInputSpec(ctx context.Context, obj interface{}) (model.HasSBOMIncludesInputSpec, error) {
	var it model.HasSBOMIncludesInputSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"software", "dependencies", "occurrences"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "software":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("software"))
			data, err := ec.unmarshalNID2ᚕstringᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.Software = data
		case "dependencies":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("dependencies"))
			data, err := ec.unmarshalNID2ᚕstringᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.Dependencies = data
		case "occurrences":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("occurrences"))
			data, err := ec.unmarshalNID2ᚕstringᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.Occurrences = data
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputHasSBOMInputSpec(ctx context.Context, obj interface{}) (model.HasSBOMInputSpec, error) {
	var it model.HasSBOMInputSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"uri", "algorithm", "digest", "downloadLocation", "origin", "collector", "knownSince"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "uri":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("uri"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.URI = data
		case "algorithm":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("algorithm"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Algorithm = data
		case "digest":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("digest"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Digest = data
		case "downloadLocation":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("downloadLocation"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.DownloadLocation = data
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
		case "knownSince":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("knownSince"))
			data, err := ec.unmarshalNTime2timeᚐTime(ctx, v)
			if err != nil {
				return it, err
			}
			it.KnownSince = data
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputHasSBOMSpec(ctx context.Context, obj interface{}) (model.HasSBOMSpec, error) {
	var it model.HasSBOMSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"id", "subject", "uri", "algorithm", "digest", "downloadLocation", "origin", "collector", "knownSince", "includedSoftware", "includedDependencies", "includedOccurrences"}
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
		case "subject":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("subject"))
			data, err := ec.unmarshalOPackageOrArtifactSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPackageOrArtifactSpec(ctx, v)
			if err != nil {
				return it, err
			}
			it.Subject = data
		case "uri":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("uri"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.URI = data
		case "algorithm":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("algorithm"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Algorithm = data
		case "digest":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("digest"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Digest = data
		case "downloadLocation":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("downloadLocation"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.DownloadLocation = data
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
		case "knownSince":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("knownSince"))
			data, err := ec.unmarshalOTime2ᚖtimeᚐTime(ctx, v)
			if err != nil {
				return it, err
			}
			it.KnownSince = data
		case "includedSoftware":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("includedSoftware"))
			data, err := ec.unmarshalOPackageOrArtifactSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPackageOrArtifactSpecᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.IncludedSoftware = data
		case "includedDependencies":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("includedDependencies"))
			data, err := ec.unmarshalOIsDependencySpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐIsDependencySpecᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.IncludedDependencies = data
		case "includedOccurrences":
			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("includedOccurrences"))
			data, err := ec.unmarshalOIsOccurrenceSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐIsOccurrenceSpecᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.IncludedOccurrences = data
		}
	}

	return it, nil
}

// endregion **************************** input.gotpl *****************************

// region    ************************** interface.gotpl ***************************

// endregion ************************** interface.gotpl ***************************

// region    **************************** object.gotpl ****************************

var hasSBOMImplementors = []string{"HasSBOM", "Node"}

func (ec *executionContext) _HasSBOM(ctx context.Context, sel ast.SelectionSet, obj *model.HasSbom) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, hasSBOMImplementors)

	out := graphql.NewFieldSet(fields)
	deferred := make(map[string]*graphql.FieldSet)
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("HasSBOM")
		case "id":
			out.Values[i] = ec._HasSBOM_id(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "subject":
			out.Values[i] = ec._HasSBOM_subject(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "uri":
			out.Values[i] = ec._HasSBOM_uri(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "algorithm":
			out.Values[i] = ec._HasSBOM_algorithm(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "digest":
			out.Values[i] = ec._HasSBOM_digest(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "downloadLocation":
			out.Values[i] = ec._HasSBOM_downloadLocation(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "origin":
			out.Values[i] = ec._HasSBOM_origin(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "collector":
			out.Values[i] = ec._HasSBOM_collector(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "knownSince":
			out.Values[i] = ec._HasSBOM_knownSince(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "includedSoftware":
			out.Values[i] = ec._HasSBOM_includedSoftware(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "includedDependencies":
			out.Values[i] = ec._HasSBOM_includedDependencies(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "includedOccurrences":
			out.Values[i] = ec._HasSBOM_includedOccurrences(ctx, field, obj)
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

func (ec *executionContext) marshalNHasSBOM2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSbomᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.HasSbom) graphql.Marshaler {
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
			ret[i] = ec.marshalNHasSBOM2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSbom(ctx, sel, v[i])
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

func (ec *executionContext) marshalNHasSBOM2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSbom(ctx context.Context, sel ast.SelectionSet, v *model.HasSbom) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._HasSBOM(ctx, sel, v)
}

func (ec *executionContext) unmarshalNHasSBOMIncludesInputSpec2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMIncludesInputSpec(ctx context.Context, v interface{}) (model.HasSBOMIncludesInputSpec, error) {
	res, err := ec.unmarshalInputHasSBOMIncludesInputSpec(ctx, v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNHasSBOMIncludesInputSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMIncludesInputSpecᚄ(ctx context.Context, v interface{}) ([]*model.HasSBOMIncludesInputSpec, error) {
	var vSlice []interface{}
	if v != nil {
		vSlice = graphql.CoerceList(v)
	}
	var err error
	res := make([]*model.HasSBOMIncludesInputSpec, len(vSlice))
	for i := range vSlice {
		ctx := graphql.WithPathContext(ctx, graphql.NewPathWithIndex(i))
		res[i], err = ec.unmarshalNHasSBOMIncludesInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMIncludesInputSpec(ctx, vSlice[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (ec *executionContext) unmarshalNHasSBOMIncludesInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMIncludesInputSpec(ctx context.Context, v interface{}) (*model.HasSBOMIncludesInputSpec, error) {
	res, err := ec.unmarshalInputHasSBOMIncludesInputSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNHasSBOMInputSpec2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMInputSpec(ctx context.Context, v interface{}) (model.HasSBOMInputSpec, error) {
	res, err := ec.unmarshalInputHasSBOMInputSpec(ctx, v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNHasSBOMInputSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMInputSpecᚄ(ctx context.Context, v interface{}) ([]*model.HasSBOMInputSpec, error) {
	var vSlice []interface{}
	if v != nil {
		vSlice = graphql.CoerceList(v)
	}
	var err error
	res := make([]*model.HasSBOMInputSpec, len(vSlice))
	for i := range vSlice {
		ctx := graphql.WithPathContext(ctx, graphql.NewPathWithIndex(i))
		res[i], err = ec.unmarshalNHasSBOMInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMInputSpec(ctx, vSlice[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (ec *executionContext) unmarshalNHasSBOMInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMInputSpec(ctx context.Context, v interface{}) (*model.HasSBOMInputSpec, error) {
	res, err := ec.unmarshalInputHasSBOMInputSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNHasSBOMSpec2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMSpec(ctx context.Context, v interface{}) (model.HasSBOMSpec, error) {
	res, err := ec.unmarshalInputHasSBOMSpec(ctx, v)
	return res, graphql.ErrorOnPath(ctx, err)
}

// endregion ***************************** type.gotpl *****************************
