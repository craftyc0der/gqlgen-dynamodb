package utils

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/craftyc0der/gqlgen-dynamodb/graph/model"
)

func GetProcessedTableName(tableName string) string {
	// split tableName on "-" and store the first element in var prefix
	prefix := strings.Split(tableName, "-")[0]
	suffix, present := os.LookupEnv("TABLE_SUFFIX_" + strings.ToUpper(prefix))
	if present {
		// replace the first instance of prefix + "-" with prefix + "-" + suffix + "-" and return tableName
		return strings.Replace(tableName, prefix+"-", prefix+"-"+suffix+"-", 1)
	}
	return tableName
}

// function passed in to do a string conversion
type stringConversion func(string) string

// the fn array is a list of functions that take a string and return a string
// only ever use the first function in the list
// we use this conceit so that it can be an optional parameter that does not require changing code else where
// or adding a lot of `, nil)` to the end of the function calls elsewhere
func ProcessTableStringFilterInput(columnName string, filter *model.TableStringFilterInput, fn ...stringConversion) ([]string, map[string]types.AttributeValue, error) {
	filterExpression := make([]string, 0)
	expressionValues := make(map[string]types.AttributeValue)

	// if there is a function passed in, use it, otherwise use the default function
	if len(fn) == 0 {
		fn = append(fn, func(s string) string { return s })
	}
	if filter.Ne != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ne", columnName, "<>", columnName))
		expressionValues[fmt.Sprintf(":%v_ne", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Ne)}
	}
	if filter.Eq != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_eq", columnName, "=", columnName))
		expressionValues[fmt.Sprintf(":%v_eq", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Eq)}
	}
	if filter.Ge != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ge", columnName, ">=", columnName))
		expressionValues[fmt.Sprintf(":%v_ge", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Ge)}
	}
	if filter.Gt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_gt", columnName, ">", columnName))
		expressionValues[fmt.Sprintf(":%v_gt", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Gt)}
	}
	if filter.Le != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_le", columnName, "<=", columnName))
		expressionValues[fmt.Sprintf(":%v_le", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Le)}
	}
	if filter.Lt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_lt", columnName, "<", columnName))
		expressionValues[fmt.Sprintf(":%v_lt", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Lt)}
	}
	if filter.BeginsWith != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("begins_with(%v, :%v_bw)", columnName, columnName))
		expressionValues[fmt.Sprintf(":%v_bw", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.BeginsWith)}
	}
	if filter.Between != nil {
		if len(filter.Between) != 2 {
			return nil, nil, fmt.Errorf("between filter must have exactly two values")
		}
		filterExpression = append(filterExpression, fmt.Sprintf("%v BETWEEN :%v_a AND :%v_b", columnName, columnName, columnName))
		expressionValues[fmt.Sprintf(":%v_a", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Between[0])}
		expressionValues[fmt.Sprintf(":%v_b", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Between[1])}
	}
	return filterExpression, expressionValues, nil
}

func ProcessTableIntFilterInput(columnName string, filter *model.TableIntFilterInput) ([]string, map[string]types.AttributeValue, error) {
	filterExpression := make([]string, 0)
	expressionValues := make(map[string]types.AttributeValue)
	if filter.Ne != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ne", columnName, "<>", columnName))
		expressionValues[fmt.Sprintf(":%v_ne", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Ne))}
	}
	if filter.Eq != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_eq", columnName, "=", columnName))
		expressionValues[fmt.Sprintf(":%v_eq", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Eq))}
	}
	if filter.Ge != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ge", columnName, ">=", columnName))
		expressionValues[fmt.Sprintf(":%v_ge", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Ge))}
	}
	if filter.Gt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_gt", columnName, ">", columnName))
		expressionValues[fmt.Sprintf(":%v_gt", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Gt))}
	}
	if filter.Le != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_le", columnName, "<=", columnName))
		expressionValues[fmt.Sprintf(":%v_le", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Le))}
	}
	if filter.Lt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_lt", columnName, "<", columnName))
		expressionValues[fmt.Sprintf(":%v_lt", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Lt))}
	}
	if filter.Between != nil {
		if len(filter.Between) != 2 {
			return nil, nil, fmt.Errorf("between filter must have exactly two values")
		}
		filterExpression = append(filterExpression, fmt.Sprintf("%v BETWEEN :%v_a AND :%v_b", columnName, columnName, columnName))
		expressionValues[fmt.Sprintf(":%v_a", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Between[0]))}
		expressionValues[fmt.Sprintf(":%v_b", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Between[1]))}
	}
	return filterExpression, expressionValues, nil
}

func ProcessTableFloatFilterInput(columnName string, filter *model.TableFloatFilterInput) ([]string, map[string]types.AttributeValue, error) {
	filterExpression := make([]string, 0)
	expressionValues := make(map[string]types.AttributeValue)
	if filter.Ne != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ne", columnName, "<>", columnName))
		expressionValues[fmt.Sprintf(":%v_ne", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Ne))}
	}
	if filter.Eq != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_eq", columnName, "=", columnName))
		expressionValues[fmt.Sprintf(":%v_eq", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Eq))}
	}
	if filter.Ge != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ge", columnName, ">=", columnName))
		expressionValues[fmt.Sprintf(":%v_ge", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Ge))}
	}
	if filter.Gt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_gt", columnName, ">", columnName))
		expressionValues[fmt.Sprintf(":%v_gt", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Gt))}
	}
	if filter.Le != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_le", columnName, "<=", columnName))
		expressionValues[fmt.Sprintf(":%v_le", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Le))}
	}
	if filter.Lt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_lt", columnName, "<", columnName))
		expressionValues[fmt.Sprintf(":%v_lt", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Lt))}
	}
	if filter.Between != nil {
		if len(filter.Between) != 2 {
			return nil, nil, fmt.Errorf("between filter must have exactly two values")
		}
		filterExpression = append(filterExpression, fmt.Sprintf("%v BETWEEN :%v_a AND :%v_b", columnName, columnName, columnName))
		expressionValues[fmt.Sprintf(":%v_a", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Between[0]))}
		expressionValues[fmt.Sprintf(":%v_b", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Between[1]))}
	}
	return filterExpression, expressionValues, nil
}

func ProcessTableBooleanFilterInput(columnName string, filter *model.TableBooleanFilterInput) ([]string, map[string]types.AttributeValue, error) {
	filterExpression := make([]string, 0)
	expressionValues := make(map[string]types.AttributeValue)
	if filter.Ne != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ne", columnName, "<>", columnName))
		expressionValues[fmt.Sprintf(":%v_ne", columnName)] = &types.AttributeValueMemberBOOL{Value: *filter.Ne}
	}
	if filter.Eq != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_eq", columnName, "=", columnName))
		expressionValues[fmt.Sprintf(":%v_eq", columnName)] = &types.AttributeValueMemberBOOL{Value: *filter.Eq}
	}
	return filterExpression, expressionValues, nil
}

func ProcessTableStringKeyInput(columnName string, filter *model.TableStringKeyInput, fn ...stringConversion) ([]string, map[string]types.AttributeValue, error) {
	filterExpression := make([]string, 0)
	expressionValues := make(map[string]types.AttributeValue)

	// if there is a function passed in, use it, otherwise use the default function
	if len(fn) == 0 {
		fn = append(fn, func(s string) string { return s })
	}
	if filter.Eq != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_eq", columnName, "=", columnName))
		expressionValues[fmt.Sprintf(":%v_eq", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Eq)}
	}
	if filter.Ge != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ge", columnName, ">=", columnName))
		expressionValues[fmt.Sprintf(":%v_ge", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Ge)}
	}
	if filter.Gt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_gt", columnName, ">", columnName))
		expressionValues[fmt.Sprintf(":%v_gt", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Gt)}
	}
	if filter.Le != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_le", columnName, "<=", columnName))
		expressionValues[fmt.Sprintf(":%v_le", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Le)}
	}
	if filter.Lt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_lt", columnName, "<", columnName))
		expressionValues[fmt.Sprintf(":%v_lt", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Lt)}
	}
	if filter.BeginsWith != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("begins_with(%v, :%v_bw)", columnName, columnName))
		expressionValues[fmt.Sprintf(":%v_bw", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.BeginsWith)}
	}
	if filter.Between != nil {
		if len(filter.Between) != 2 {
			return nil, nil, fmt.Errorf("between filter must have exactly two values")
		}
		filterExpression = append(filterExpression, fmt.Sprintf("%v BETWEEN :%v_a AND :%v_b", columnName, columnName, columnName))
		expressionValues[fmt.Sprintf(":%v_a", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Between[0])}
		expressionValues[fmt.Sprintf(":%v_b", columnName)] = &types.AttributeValueMemberS{Value: fn[0](*filter.Between[1])}
	}
	return filterExpression, expressionValues, nil
}

func ProcessTableIntKeyInput(columnName string, filter *model.TableIntKeyInput) ([]string, map[string]types.AttributeValue, error) {
	filterExpression := make([]string, 0)
	expressionValues := make(map[string]types.AttributeValue)
	if filter.Eq != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_eq", columnName, "=", columnName))
		expressionValues[fmt.Sprintf(":%v_eq", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Eq))}
	}
	if filter.Ge != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ge", columnName, ">=", columnName))
		expressionValues[fmt.Sprintf(":%v_ge", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Ge))}
	}
	if filter.Gt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_gt", columnName, ">", columnName))
		expressionValues[fmt.Sprintf(":%v_gt", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Gt))}
	}
	if filter.Le != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_le", columnName, "<=", columnName))
		expressionValues[fmt.Sprintf(":%v_le", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Le))}
	}
	if filter.Lt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_lt", columnName, "<", columnName))
		expressionValues[fmt.Sprintf(":%v_lt", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Lt))}
	}
	if filter.Between != nil {
		if len(filter.Between) != 2 {
			return nil, nil, fmt.Errorf("between filter must have exactly two values")
		}
		filterExpression = append(filterExpression, fmt.Sprintf("%v BETWEEN :%v_a AND :%v_b", columnName, columnName, columnName))
		expressionValues[fmt.Sprintf(":%v_a", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Between[0]))}
		expressionValues[fmt.Sprintf(":%v_b", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(*filter.Between[1]))}
	}
	return filterExpression, expressionValues, nil
}

func ProcessTableFloatKeyInput(columnName string, filter *model.TableFloatKeyInput) ([]string, map[string]types.AttributeValue, error) {
	filterExpression := make([]string, 0)
	expressionValues := make(map[string]types.AttributeValue)
	if filter.Eq != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_eq", columnName, "=", columnName))
		expressionValues[fmt.Sprintf(":%v_eq", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Eq))}
	}
	if filter.Ge != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_ge", columnName, ">=", columnName))
		expressionValues[fmt.Sprintf(":%v_ge", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Ge))}
	}
	if filter.Gt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_gt", columnName, ">", columnName))
		expressionValues[fmt.Sprintf(":%v_gt", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Gt))}
	}
	if filter.Le != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_le", columnName, "<=", columnName))
		expressionValues[fmt.Sprintf(":%v_le", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Le))}
	}
	if filter.Lt != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_lt", columnName, "<", columnName))
		expressionValues[fmt.Sprintf(":%v_lt", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Lt))}
	}
	if filter.Between != nil {
		if len(filter.Between) != 2 {
			return nil, nil, fmt.Errorf("between filter must have exactly two values")
		}
		filterExpression = append(filterExpression, fmt.Sprintf("%v BETWEEN :%v_a AND :%v_b", columnName, columnName, columnName))
		expressionValues[fmt.Sprintf(":%v_a", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Between[0]))}
		expressionValues[fmt.Sprintf(":%v_b", columnName)] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", float64(*filter.Between[1]))}
	}
	return filterExpression, expressionValues, nil
}

func ProcessTableBooleanKeyInput(columnName string, filter *model.TableBooleanKeyInput) ([]string, map[string]types.AttributeValue, error) {
	filterExpression := make([]string, 0)
	expressionValues := make(map[string]types.AttributeValue)
	if filter.Eq != nil {
		filterExpression = append(filterExpression, fmt.Sprintf("%v %v :%v_eq", columnName, "=", columnName))
		expressionValues[fmt.Sprintf(":%v_eq", columnName)] = &types.AttributeValueMemberBOOL{Value: *filter.Eq}
	}
	return filterExpression, expressionValues, nil
}
