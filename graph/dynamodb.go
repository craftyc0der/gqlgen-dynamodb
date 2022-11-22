package graph

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/craftyc0der/gqlgen-dynamodb/graph/generated"
	"github.com/lithammer/shortuuid/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
)

var AwsConfig = func(o *config.LoadOptions) error {
	o.Region = "us-east-2"
	return nil
}

var DynamodbConfig = func(o *dynamodb.Options) {}

var (
	//Metrics
	QueryCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "graphql_query_count",
		Help: "We will count all the queries made by name.",
	}, []string{"query_name"})
	QueryAuthFailureCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "graphql_query_auth_failure_count",
		Help: "We will count all the query auth failures by name.",
	}, []string{"query_name", "role"})
	QueryFailureCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "graphql_query_failure_count",
		Help: "We will count all the query failures by name.",
	}, []string{"query_name"})
	QueryTimer = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "graphql_query_duration_seconds",
		Help: "Execution time for each query.",
	}, []string{"query_name"})
	QueryHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "graphql_query_request_time_seconds",
		Help: "Histogram of execution time for each query.",
	}, []string{"query_name"})
)

func init() {
	// if environment variable LOCAL is true, then we will use the local dynamodb
	// otherwise we will use the real dynamodb
	local, present := os.LookupEnv("LOCAL")
	if present {
		if local != "false" {
			AwsConfig = func(o *config.LoadOptions) error {
				return nil
			}

			DynamodbConfig = func(o *dynamodb.Options) {
				o.EndpointResolver = dynamodb.EndpointResolverFromURL(local)
			}
		}
	}
	fmt.Print(otelaws.RegionKey)
}

func GetUUID() string {
	return shortuuid.New()
}

func ProcessInputMapRemoveUnderscoreIfNumberKey(inputMap interface{}) map[string]interface{} {
	_inputMap, ok := inputMap.(map[string]interface{})
	if ok {
		for key, value := range _inputMap {
			// remove first key character if _ and test if resulting string is number
			if key[0] == '_' && len(key) > 1 {
				if _, err := strconv.Atoi(key[1:]); err == nil {
					delete(_inputMap, key)
					_value, okk := value.(map[string]interface{})
					if okk {
						_inputMap[key[1:]] = ProcessInputMapRemoveUnderscoreIfNumberKey(_value)
					} else {
						_inputMap[key[1:]] = value
					}
				}
			}
		}
	}
	return _inputMap
}

func GetDefaultHandler() *handler.Server {
	config := generated.Config{Resolvers: &Resolver{}}

	// these need to implement the interface defined in generated.go
	config.Directives.AuthorizedRole = func(ctx context.Context, obj interface{}, next graphql.Resolver, serviceRoles []string, userRoles []string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.CustomResolver = func(ctx context.Context, obj interface{}, next graphql.Resolver, packageArg string, function string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.DynamodbColumn = func(ctx context.Context, obj interface{}, next graphql.Resolver, fieldName string, fieldType string, jsonName *string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.DynamodbHashKey = func(ctx context.Context, obj interface{}, next graphql.Resolver) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.DynamodbQuery = func(ctx context.Context, obj interface{}, next graphql.Resolver, table string, projectionExpression *string, index *string, limit *int, sortColumn *string, sortAsc *bool, scanIndexBackward *bool, consistentRead *bool, insert *bool, update *bool, delete *bool, updateConditionExpression *string, updateConditionValues []string, updateConditionError *string, deleteConditionExpression *string, deleteConditionValues []string, deleteConditionError *string, preQueryPackage *string, preQueryFunction *string, postQueryPackage *string, postQueryFunction *string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.DynamodbRangeKey = func(ctx context.Context, obj interface{}, next graphql.Resolver) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.DynamodbSubquery = func(ctx context.Context, obj interface{}, next graphql.Resolver, foreignHashKey string, foreignHashKeyRequired bool, hashKeyModelName string, hashKeyFieldName string, hashKeyFieldType string, parentHashKeyModelName string, foreignRangeKey *string, foreignRangeKeyRequired *bool, rangeKeyModelName *string, rangeKeyFieldName *string, rangeKeyFieldType *string, parentRangeKeyModelName *string, className string, table string, limit *int) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.CustomSubquery = func(ctx context.Context, obj interface{}, next graphql.Resolver, packageArg string, function string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.Example = func(ctx context.Context, obj interface{}, next graphql.Resolver, value string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.Hash = func(ctx context.Context, obj interface{}, next graphql.Resolver, fieldName string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.Immutable = func(ctx context.Context, obj interface{}, next graphql.Resolver, errorMessage string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.Timestamp = func(ctx context.Context, obj interface{}, next graphql.Resolver, immutable bool) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.Uuid = func(ctx context.Context, obj interface{}, next graphql.Resolver, hashKey bool) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.DefaultValue = func(ctx context.Context, obj interface{}, next graphql.Resolver, envVar *string, static *string, variable *string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.MutationCondition = func(ctx context.Context, obj interface{}, next graphql.Resolver, expression string) (res interface{}, err error) {
		return next(ctx)
	}
	config.Directives.ArrayInputUnique = func(ctx context.Context, obj interface{}, next graphql.Resolver, fieldName string, exceptionRegex *string) (res interface{}, err error) {
		return next(ctx)
	}
	// NewExecutableSchema and Config are in the generated.go file
	// Resolver is in the resolver.go file
	return handler.NewDefaultServer(generated.NewExecutableSchema(config))
}

func GetPreloads(ctx context.Context) map[string]struct{} {
	slice := GetNestedPreloads(
		graphql.GetOperationContext(ctx),
		graphql.CollectFieldsCtx(ctx, nil),
		"",
	)
	preloads := make(map[string]struct{}, len(slice))
	// add all members of slice to preloads
	for _, preload := range slice {
		//lint:ignore SA1019 Ignore the deprecation warnings
		preloads[strings.Title(preload)] = struct{}{}
	}
	return preloads
}

func GetNestedPreloads(ctx *graphql.OperationContext, fields []graphql.CollectedField, prefix string) (preloads []string) {
	for _, column := range fields {
		prefixColumn := GetPreloadString(prefix, column.Name)
		preloads = append(preloads, prefixColumn)
		preloads = append(preloads, GetNestedPreloads(ctx, graphql.CollectFields(ctx, column.Selections, nil), prefixColumn)...)
	}
	return
}

func GetPreloadString(prefix, name string) string {
	if len(prefix) > 0 {
		return prefix + "." + name
	}
	return name
}

type QueryLog struct {
	Name      string      `json:"name"`
	TraceId   string      `json:"traceID"`
	Arguments interface{} `json:"arguments"`
}
