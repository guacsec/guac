package resolvers

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/99designs/gqlgen/graphql"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func isStructOrPointerToStruct(v reflect.Value) (reflect.Value, bool) {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	return v, v.Kind() == reflect.Struct
}

func fieldMatches(item reflect.Value, keyName, value string, operation model.FilterOperation) bool {
	for i := 0; i < item.NumField(); i++ {
		fieldName := item.Type().Field(i).Name
		fieldValue := fmt.Sprintf("%v", item.Field(i).Interface())

		if strings.EqualFold(fieldName, keyName) {
			lowercaseValue := strings.ToLower(value)
			lowercaseFieldValue := strings.ToLower(fieldValue)

			switch operation {
			case model.FilterOperationContains:
				if strings.Contains(lowercaseFieldValue, lowercaseValue) {
					return true
				}
			case model.FilterOperationStartswith:
				if strings.HasPrefix(lowercaseFieldValue, lowercaseValue) {
					return true
				}
			}
		}
	}

	return false
}

func createMatchingItemsInterface(modelType reflect.Type, matchingItems []reflect.Value) reflect.Value {
	matchingItemsInterface := reflect.MakeSlice(reflect.SliceOf(reflect.PtrTo(modelType)), len(matchingItems), len(matchingItems))
	for i := 0; i < len(matchingItems); i++ {
		matchingItemsInterface.Index(i).Set(matchingItems[i].Addr())
	}
	return matchingItemsInterface
}

const numWorkers = 5

func worker(ctx context.Context, input reflect.Value, start, end int, keyName, value string, operation model.FilterOperation, resultChan chan<- reflect.Value) {
	matchingItems := make([]reflect.Value, 0, end-start)

	for i := start; i < end; i++ {
		item := input.Index(i)
		item, isStruct := isStructOrPointerToStruct(item)

		if isStruct && fieldMatches(item, keyName, value, operation) {
			matchingItems = append(matchingItems, item)
		}
	}

	for _, item := range matchingItems {
		resultChan <- item
	}
}


func Filter(ctx context.Context, obj interface{}, next graphql.Resolver, keyName *string, operation *model.FilterOperation, value *string) (res interface{}, err error) {
    result, err := next(ctx)
    if err != nil {
        return nil, err
    }

    v := reflect.ValueOf(result)
    if v.Kind() == reflect.Slice && v.Len() > 0 {
        modelType := v.Index(0).Type().Elem()
        partSize := v.Len() / numWorkers
        resultChan := make(chan reflect.Value, numWorkers)
        var wg sync.WaitGroup

        for i := 0; i < numWorkers; i++ {
            start := i * partSize
            end := start + partSize
            if i == numWorkers-1 {
                end = v.Len()
            }
            wg.Add(1)

            go func(start, end int) {
                defer wg.Done()
                worker(ctx, v, start, end, *keyName, *value, *operation, resultChan)
            }(start, end)
        }

        go func() {
            wg.Wait()
            close(resultChan)
        }()

        totalMatchingItems := collectResults(resultChan)
        matchingItemsInterface := createMatchingItemsInterface(modelType, totalMatchingItems)

        return matchingItemsInterface.Interface(), nil
    } else {
        return result, nil
    }
}

func collectResults(resultChan <-chan reflect.Value) []reflect.Value {
    var totalMatchingItems []reflect.Value

    for item := range resultChan {
        totalMatchingItems = append(totalMatchingItems, item)
    }

    return totalMatchingItems
}

