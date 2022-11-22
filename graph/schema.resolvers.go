package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/craftyc0der/gqlgen-dynamodb/graph/custom"
	"github.com/craftyc0der/gqlgen-dynamodb/graph/generated"
	"github.com/craftyc0der/gqlgen-dynamodb/graph/model"
	"github.com/craftyc0der/gqlgen-dynamodb/graph/utils"
	"github.com/craftyc0der/gqlgen-dynamodb/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func (r *mutationResolver) CreateApplicationUser(ctx context.Context, userName string, companyID string) (*model.ApplicationUserList, error) {
	QueryCounter.WithLabelValues("CreateApplicationUser").Inc()
	start := time.Now()
	startTimer := prometheus.NewTimer(prometheus.ObserverFunc(QueryTimer.WithLabelValues("CreateApplicationUser").Set))
	defer func() {
		QueryHistogram.WithLabelValues("CreateApplicationUser").Observe(time.Since(start).Seconds())
		startTimer.ObserveDuration()
	}()
	oldspan := trace.SpanFromContext(ctx)
	tracer := oldspan.TracerProvider().Tracer("CreateApplicationUser")
	awsContext, span := tracer.Start(ctx, "CreateApplicationUser")
	defer span.End()
	span.SetAttributes(attribute.String("userName", userName))
	span.SetAttributes(attribute.String("companyID", companyID))
	queryLog := &QueryLog{
		Name:    "CreateApplicationUser",
		TraceId: oldspan.SpanContext().TraceID().String(),
		Arguments: map[string]interface{}{
			"userName":  userName,
			"companyID": companyID,
		},
	}
	ql, _ := json.Marshal(queryLog)
	fmt.Println(string(ql))

	cfg, err := config.LoadDefaultConfig(awsContext, AwsConfig)
	otelaws.AppendMiddlewares(&cfg.APIOptions)

	allowedServiceRoles := []string{"service-one"}
	allowedUserRoles := []string{"system-admin"}
	_allowed, currentLoggedInRole := middleware.RoleAllowed(ctx, allowedServiceRoles, allowedUserRoles)
	if !_allowed {
		QueryAuthFailureCounter.WithLabelValues("CreateApplicationUser", currentLoggedInRole).Inc()
		err = errors.New("unauthorized role: " + currentLoggedInRole)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	if err == nil {
		db := dynamodb.NewFromConfig(cfg, DynamodbConfig)

		createDate := int(time.Now().UnixMilli())

		userID := GetUUID()

		pii := &dynamodb.PutItemInput{
			TableName: aws.String(utils.GetProcessedTableName("application-user")),
			Item: map[string]types.AttributeValue{
				"_updatedDate": &types.AttributeValueMemberN{Value: strconv.Itoa(int(time.Now().UnixMilli()))},
				"companyId":    &types.AttributeValueMemberS{Value: companyID},
				"createDate":   &types.AttributeValueMemberN{Value: strconv.Itoa(createDate)},
				"userId":       &types.AttributeValueMemberS{Value: userID},
				"userName":     &types.AttributeValueMemberS{Value: userName},
			},
		}

		_, err = db.PutItem(awsContext, pii)

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("CreateApplicationUser").Inc()
			return nil, err
		}

		var result model.ApplicationUserList
		items := []model.ApplicationUser{}
		filterExpression := make([]string, 0)
		eav := make(map[string]types.AttributeValue)
		kce := []string{}

		eav[":userId"] = &types.AttributeValueMemberS{Value: userID}
		kce = append(kce, "userId=:userId")

		qi := &dynamodb.QueryInput{
			TableName:                 aws.String(utils.GetProcessedTableName("application-user")),
			KeyConditionExpression:    aws.String(strings.Join(kce, " and ")),
			FilterExpression:          aws.String(strings.Join(filterExpression, " and ")),
			ExpressionAttributeValues: eav,
			ConsistentRead:            aws.Bool(true),
		}
		if len(filterExpression) == 0 {
			qi.FilterExpression = nil
		}
		p := dynamodb.NewQueryPaginator(db, qi)
		var out *dynamodb.QueryOutput
		var err error
		for p.HasMorePages() {
			out, err = p.NextPage(awsContext)
			if err == nil {
				if out.Count > 0 {
					err = attributevalue.UnmarshalListOfMaps(out.Items, &items)
					if err != nil {
						break
					}
					for i := 0; i < len(items); i++ {
						result.Items = append(result.Items, &items[i])
					}
				}
			} else {
				break
			}
		}

		// start subquery Company
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.Company"]; ok {
			if len(result.Items) > 0 {
				Company := []model.ApplicationCompany{}
				CompanyIDMap := make(map[string][]string)
				ApplicationUserMap := make(map[string]*model.ApplicationUser)
				CompanyIDkeys := make([]map[string]types.AttributeValue, 0)
				for i := 0; i < len(result.Items); i++ {
					if result.Items[i].CompanyID != nil {
						ApplicationUserMap[result.Items[i].UserID] = result.Items[i]
						_, ok := CompanyIDMap[*result.Items[i].CompanyID]
						if !ok {
							CompanyIDMap[*result.Items[i].CompanyID] = make([]string, 0)
							CompanyIDkeys = append(CompanyIDkeys, map[string]types.AttributeValue{"companyId": &types.AttributeValueMemberS{Value: *result.Items[i].CompanyID}})
						}
						CompanyIDMap[*result.Items[i].CompanyID] = append(CompanyIDMap[*result.Items[i].CompanyID], result.Items[i].UserID)
					}
				}
				if len(CompanyIDkeys) > 0 {
					CompanyIDBatchGet, CompanyIDErr := db.BatchGetItem(awsContext, &dynamodb.BatchGetItemInput{
						RequestItems: map[string]types.KeysAndAttributes{
							utils.GetProcessedTableName("application-company"): {
								Keys: CompanyIDkeys,
							},
						},
					})
					if CompanyIDErr == nil {
						if len(CompanyIDBatchGet.Responses[utils.GetProcessedTableName("application-company")]) > 0 {
							err = attributevalue.UnmarshalListOfMaps(CompanyIDBatchGet.Responses[utils.GetProcessedTableName("application-company")], &Company)
							for i := 0; i < len(Company); i++ {
								for j := 0; j < len(CompanyIDMap[Company[i].CompanyID]); j++ {
									userID := CompanyIDMap[Company[i].CompanyID][j]
									if entry, ok := ApplicationUserMap[userID]; ok {
										entry.Company = &Company[i]
									}
								}
							}
						}
					} else {
						err = CompanyIDErr
					}
				}
			}
		}
		// end subquery Company

		// start subquery Languages
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.Languages"]; ok {
			if len(result.Items) > 0 {
				UserIDMap := make(map[string][]string)
				ApplicationUserMap := make(map[string]*model.ApplicationUser)
				for i := 0; i < len(result.Items); i++ {
					ApplicationUserMap[result.Items[i].UserID] = result.Items[i]
					_, ok := UserIDMap[result.Items[i].UserID]
					if !ok {
						UserIDMap[result.Items[i].UserID] = make([]string, 0)
						UserIDMap[result.Items[i].UserID] = append(UserIDMap[result.Items[i].UserID], result.Items[i].UserID)
						qieav := make(map[string]types.AttributeValue)
						qikce := []string{}
						qieav[":userId"] = &types.AttributeValueMemberS{Value: result.Items[i].UserID}
						qikce = append(qikce, "userId=:userId")
						qi := &dynamodb.QueryInput{
							TableName:                 aws.String(utils.GetProcessedTableName("application-userLanguage")),
							KeyConditionExpression:    aws.String(strings.Join(qikce, " and ")),
							ExpressionAttributeValues: qieav,
							ConsistentRead:            aws.Bool(true),
						}
						p := dynamodb.NewQueryPaginator(db, qi)
						var out *dynamodb.QueryOutput
						var err error
						for p.HasMorePages() {
							Languages := []model.ApplicationUserLanguage{}
							out, err = p.NextPage(awsContext)
							if err == nil {
								if out.Count > 0 {
									err = attributevalue.UnmarshalListOfMaps(out.Items, &Languages)
									if err != nil {
										break
									}
									for j := 0; j < len(Languages); j++ {
										ApplicationUserMap[result.Items[i].UserID].Languages = append(ApplicationUserMap[result.Items[i].UserID].Languages, &Languages[j])
									}
								} else {
									ApplicationUserMap[result.Items[i].UserID].Languages = make([]*model.ApplicationUserLanguage, 0)
								}
							} else {
								break
							}
						}
					}
				}
			}
		}

		// start subquery CustomData
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.CustomData"]; ok {
			if len(result.Items) > 0 {
				custom.GetCustomData(ctx, GetPreloads(ctx), &result)
			}
		}
		// end subquery CustomData

		span.AddEvent("results", trace.WithAttributes(attribute.Int("count", len(result.Items))))

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("CreateApplicationUser").Inc()
		}
		return &result, err

	} else {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		QueryFailureCounter.WithLabelValues("CreateApplicationUser").Inc()
	}
	return nil, nil
}

func (r *mutationResolver) UpdateApplicationUser(ctx context.Context, userID string, userName string, companyID string) (*model.ApplicationUserList, error) {
	QueryCounter.WithLabelValues("UpdateApplicationUser").Inc()
	start := time.Now()
	startTimer := prometheus.NewTimer(prometheus.ObserverFunc(QueryTimer.WithLabelValues("UpdateApplicationUser").Set))
	defer func() {
		QueryHistogram.WithLabelValues("UpdateApplicationUser").Observe(time.Since(start).Seconds())
		startTimer.ObserveDuration()
	}()
	oldspan := trace.SpanFromContext(ctx)
	tracer := oldspan.TracerProvider().Tracer("UpdateApplicationUser")
	awsContext, span := tracer.Start(ctx, "UpdateApplicationUser")
	defer span.End()
	span.SetAttributes(attribute.String("userID", userID))
	span.SetAttributes(attribute.String("userName", userName))
	span.SetAttributes(attribute.String("companyID", companyID))
	queryLog := &QueryLog{
		Name:    "UpdateApplicationUser",
		TraceId: oldspan.SpanContext().TraceID().String(),
		Arguments: map[string]interface{}{
			"userID":    userID,
			"userName":  userName,
			"companyID": companyID,
		},
	}
	ql, _ := json.Marshal(queryLog)
	fmt.Println(string(ql))

	cfg, err := config.LoadDefaultConfig(awsContext, AwsConfig)
	otelaws.AppendMiddlewares(&cfg.APIOptions)

	allowedServiceRoles := []string{"service-one"}
	allowedUserRoles := []string{"system-admin"}
	_allowed, currentLoggedInRole := middleware.RoleAllowed(ctx, allowedServiceRoles, allowedUserRoles)
	if !_allowed {
		QueryAuthFailureCounter.WithLabelValues("UpdateApplicationUser", currentLoggedInRole).Inc()
		err = errors.New("unauthorized role: " + currentLoggedInRole)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	if err == nil {
		db := dynamodb.NewFromConfig(cfg, DynamodbConfig)

		expressions := make([]string, 0)
		removeExpression := make([]string, 0)
		updateExpression := make([]string, 0)
		conditionalExpressions := make([]string, 0)
		ueav := make(map[string]types.AttributeValue)
		updateExpression = append(updateExpression, "#UD = :updatedDate")
		ueav[":updatedDate"] = &types.AttributeValueMemberN{Value: strconv.Itoa(int(time.Now().UnixMilli()))}
		if companyID == "" {
			removeExpression = append(removeExpression, "companyId")
		} else {
			updateExpression = append(updateExpression, "companyId = :companyId")
			ueav[":companyId"] = &types.AttributeValueMemberS{Value: companyID}
		}
		conditionalExpressions = append(conditionalExpressions, "userId = :userId")
		ueav[":userId"] = &types.AttributeValueMemberS{Value: userID}
		conditionalExpressions = append(conditionalExpressions, "userName = :userName")
		ueav[":userName"] = &types.AttributeValueMemberS{Value: userName}

		ue := ""
		if len(updateExpression) > 0 {
			ue += "SET "
			ue += strings.Join(updateExpression, ", ")
			expressions = append(expressions, ue)
		}
		re := ""
		if len(removeExpression) > 0 {
			re += "REMOVE "
			re += strings.Join(removeExpression, ", ")
			expressions = append(expressions, re)
		}
		uii := &dynamodb.UpdateItemInput{
			TableName: aws.String(utils.GetProcessedTableName("application-user")),
			Key: map[string]types.AttributeValue{
				"userId":   &types.AttributeValueMemberS{Value: userID},
				"userName": &types.AttributeValueMemberS{Value: userName},
			},
			UpdateExpression:          aws.String(strings.Join(expressions, "\n ")),
			ConditionExpression:       aws.String(strings.Join(conditionalExpressions, " and ")),
			ExpressionAttributeValues: ueav,
			ExpressionAttributeNames: map[string]string{
				"#UD": *aws.String("_updatedDate"),
			},
		}
		if len(ueav) == 0 {
			uii.ExpressionAttributeValues = nil
		}
		_, err = db.UpdateItem(awsContext, uii)
		if err != nil {
			if strings.Contains(err.Error(), "ConditionalCheckFailedException") {
				err = errors.New("update failed due to constraint mismatch")
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("UpdateApplicationUser").Inc()
			return nil, err
		}

		var result model.ApplicationUserList
		items := []model.ApplicationUser{}
		filterExpression := make([]string, 0)
		eav := make(map[string]types.AttributeValue)
		kce := []string{}

		eav[":userId"] = &types.AttributeValueMemberS{Value: userID}
		kce = append(kce, "userId=:userId")

		eav[":userName"] = &types.AttributeValueMemberS{Value: userName}
		kce = append(kce, "userName=:userName")

		qi := &dynamodb.QueryInput{
			TableName:                 aws.String(utils.GetProcessedTableName("application-user")),
			KeyConditionExpression:    aws.String(strings.Join(kce, " and ")),
			FilterExpression:          aws.String(strings.Join(filterExpression, " and ")),
			ExpressionAttributeValues: eav,
			ConsistentRead:            aws.Bool(true),
		}
		if len(filterExpression) == 0 {
			qi.FilterExpression = nil
		}
		p := dynamodb.NewQueryPaginator(db, qi)
		var out *dynamodb.QueryOutput
		var err error
		for p.HasMorePages() {
			out, err = p.NextPage(awsContext)
			if err == nil {
				if out.Count > 0 {
					err = attributevalue.UnmarshalListOfMaps(out.Items, &items)
					if err != nil {
						break
					}
					for i := 0; i < len(items); i++ {
						result.Items = append(result.Items, &items[i])
					}
				}
			} else {
				break
			}
		}

		// start subquery Company
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.Company"]; ok {
			if len(result.Items) > 0 {
				Company := []model.ApplicationCompany{}
				CompanyIDMap := make(map[string][]string)
				ApplicationUserMap := make(map[string]*model.ApplicationUser)
				CompanyIDkeys := make([]map[string]types.AttributeValue, 0)
				for i := 0; i < len(result.Items); i++ {
					if result.Items[i].CompanyID != nil {
						ApplicationUserMap[result.Items[i].UserID] = result.Items[i]
						_, ok := CompanyIDMap[*result.Items[i].CompanyID]
						if !ok {
							CompanyIDMap[*result.Items[i].CompanyID] = make([]string, 0)
							CompanyIDkeys = append(CompanyIDkeys, map[string]types.AttributeValue{"companyId": &types.AttributeValueMemberS{Value: *result.Items[i].CompanyID}})
						}
						CompanyIDMap[*result.Items[i].CompanyID] = append(CompanyIDMap[*result.Items[i].CompanyID], result.Items[i].UserID)
					}
				}
				if len(CompanyIDkeys) > 0 {
					CompanyIDBatchGet, CompanyIDErr := db.BatchGetItem(awsContext, &dynamodb.BatchGetItemInput{
						RequestItems: map[string]types.KeysAndAttributes{
							utils.GetProcessedTableName("application-company"): {
								Keys: CompanyIDkeys,
							},
						},
					})
					if CompanyIDErr == nil {
						if len(CompanyIDBatchGet.Responses[utils.GetProcessedTableName("application-company")]) > 0 {
							err = attributevalue.UnmarshalListOfMaps(CompanyIDBatchGet.Responses[utils.GetProcessedTableName("application-company")], &Company)
							for i := 0; i < len(Company); i++ {
								for j := 0; j < len(CompanyIDMap[Company[i].CompanyID]); j++ {
									userID := CompanyIDMap[Company[i].CompanyID][j]
									if entry, ok := ApplicationUserMap[userID]; ok {
										entry.Company = &Company[i]
									}
								}
							}
						}
					} else {
						err = CompanyIDErr
					}
				}
			}
		}
		// end subquery Company

		// start subquery Languages
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.Languages"]; ok {
			if len(result.Items) > 0 {
				UserIDMap := make(map[string][]string)
				ApplicationUserMap := make(map[string]*model.ApplicationUser)
				for i := 0; i < len(result.Items); i++ {
					ApplicationUserMap[result.Items[i].UserID] = result.Items[i]
					_, ok := UserIDMap[result.Items[i].UserID]
					if !ok {
						UserIDMap[result.Items[i].UserID] = make([]string, 0)
						UserIDMap[result.Items[i].UserID] = append(UserIDMap[result.Items[i].UserID], result.Items[i].UserID)
						qieav := make(map[string]types.AttributeValue)
						qikce := []string{}
						qieav[":userId"] = &types.AttributeValueMemberS{Value: result.Items[i].UserID}
						qikce = append(qikce, "userId=:userId")
						qi := &dynamodb.QueryInput{
							TableName:                 aws.String(utils.GetProcessedTableName("application-userLanguage")),
							KeyConditionExpression:    aws.String(strings.Join(qikce, " and ")),
							ExpressionAttributeValues: qieav,
							ConsistentRead:            aws.Bool(true),
						}
						p := dynamodb.NewQueryPaginator(db, qi)
						var out *dynamodb.QueryOutput
						var err error
						for p.HasMorePages() {
							Languages := []model.ApplicationUserLanguage{}
							out, err = p.NextPage(awsContext)
							if err == nil {
								if out.Count > 0 {
									err = attributevalue.UnmarshalListOfMaps(out.Items, &Languages)
									if err != nil {
										break
									}
									for j := 0; j < len(Languages); j++ {
										ApplicationUserMap[result.Items[i].UserID].Languages = append(ApplicationUserMap[result.Items[i].UserID].Languages, &Languages[j])
									}
								} else {
									ApplicationUserMap[result.Items[i].UserID].Languages = make([]*model.ApplicationUserLanguage, 0)
								}
							} else {
								break
							}
						}
					}
				}
			}
		}

		// start subquery CustomData
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.CustomData"]; ok {
			if len(result.Items) > 0 {
				custom.GetCustomData(ctx, GetPreloads(ctx), &result)
			}
		}
		// end subquery CustomData

		span.AddEvent("results", trace.WithAttributes(attribute.Int("count", len(result.Items))))

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("UpdateApplicationUser").Inc()
		}
		return &result, err

	} else {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		QueryFailureCounter.WithLabelValues("UpdateApplicationUser").Inc()
	}
	return nil, nil
}

func (r *mutationResolver) CreateApplicationUserLanguage(ctx context.Context, userID string, userLanguage string) (*model.ApplicationUserLanguageList, error) {
	QueryCounter.WithLabelValues("CreateApplicationUserLanguage").Inc()
	start := time.Now()
	startTimer := prometheus.NewTimer(prometheus.ObserverFunc(QueryTimer.WithLabelValues("CreateApplicationUserLanguage").Set))
	defer func() {
		QueryHistogram.WithLabelValues("CreateApplicationUserLanguage").Observe(time.Since(start).Seconds())
		startTimer.ObserveDuration()
	}()
	oldspan := trace.SpanFromContext(ctx)
	tracer := oldspan.TracerProvider().Tracer("CreateApplicationUserLanguage")
	awsContext, span := tracer.Start(ctx, "CreateApplicationUserLanguage")
	defer span.End()
	span.SetAttributes(attribute.String("userID", userID))
	span.SetAttributes(attribute.String("userLanguage", userLanguage))
	queryLog := &QueryLog{
		Name:    "CreateApplicationUserLanguage",
		TraceId: oldspan.SpanContext().TraceID().String(),
		Arguments: map[string]interface{}{
			"userID":       userID,
			"userLanguage": userLanguage,
		},
	}
	ql, _ := json.Marshal(queryLog)
	fmt.Println(string(ql))

	cfg, err := config.LoadDefaultConfig(awsContext, AwsConfig)
	otelaws.AppendMiddlewares(&cfg.APIOptions)

	allowedServiceRoles := []string{"service-one"}
	allowedUserRoles := []string{"system-admin"}
	_allowed, currentLoggedInRole := middleware.RoleAllowed(ctx, allowedServiceRoles, allowedUserRoles)
	if !_allowed {
		QueryAuthFailureCounter.WithLabelValues("CreateApplicationUserLanguage", currentLoggedInRole).Inc()
		err = errors.New("unauthorized role: " + currentLoggedInRole)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	if err == nil {
		db := dynamodb.NewFromConfig(cfg, DynamodbConfig)

		getItem, getItemErr := db.GetItem(awsContext, &dynamodb.GetItemInput{
			TableName: aws.String(utils.GetProcessedTableName("application-userLanguage")),
			Key: map[string]types.AttributeValue{
				"userId":       &types.AttributeValueMemberS{Value: userID},
				"userLanguage": &types.AttributeValueMemberS{Value: userLanguage},
			},
		})
		var currentItem model.ApplicationUserLanguage
		if getItemErr == nil {
			attributevalue.UnmarshalMap(getItem.Item, &currentItem)
		}
		currentItemExists := false
		if currentItem.UserID == userID && currentItem.UserLanguage == userLanguage {
			currentItemExists = true
		}

		if currentItemExists {
			return nil, fmt.Errorf("userID - userLanguage already exists: %v - %v", userID, userLanguage)
		}

		pii := &dynamodb.PutItemInput{
			TableName: aws.String(utils.GetProcessedTableName("application-userLanguage")),
			Item: map[string]types.AttributeValue{
				"_updatedDate": &types.AttributeValueMemberN{Value: strconv.Itoa(int(time.Now().UnixMilli()))},
				"userId":       &types.AttributeValueMemberS{Value: userID},
				"userLanguage": &types.AttributeValueMemberS{Value: userLanguage},
			},
		}

		_, err = db.PutItem(awsContext, pii)

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("CreateApplicationUserLanguage").Inc()
			return nil, err
		}

		var result model.ApplicationUserLanguageList
		items := []model.ApplicationUserLanguage{}
		filterExpression := make([]string, 0)
		eav := make(map[string]types.AttributeValue)
		kce := []string{}

		eav[":userId"] = &types.AttributeValueMemberS{Value: userID}
		kce = append(kce, "userId=:userId")

		eav[":userLanguage"] = &types.AttributeValueMemberS{Value: userLanguage}
		kce = append(kce, "userLanguage=:userLanguage")

		qi := &dynamodb.QueryInput{
			TableName:                 aws.String(utils.GetProcessedTableName("application-userLanguage")),
			KeyConditionExpression:    aws.String(strings.Join(kce, " and ")),
			FilterExpression:          aws.String(strings.Join(filterExpression, " and ")),
			ExpressionAttributeValues: eav,
			ConsistentRead:            aws.Bool(true),
		}
		if len(filterExpression) == 0 {
			qi.FilterExpression = nil
		}
		p := dynamodb.NewQueryPaginator(db, qi)
		var out *dynamodb.QueryOutput
		var err error
		for p.HasMorePages() {
			out, err = p.NextPage(awsContext)
			if err == nil {
				if out.Count > 0 {
					err = attributevalue.UnmarshalListOfMaps(out.Items, &items)
					if err != nil {
						break
					}
					for i := 0; i < len(items); i++ {
						result.Items = append(result.Items, &items[i])
					}
				}
			} else {
				break
			}
		}

		span.AddEvent("results", trace.WithAttributes(attribute.Int("count", len(result.Items))))

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("CreateApplicationUserLanguage").Inc()
		}
		return &result, err

	} else {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		QueryFailureCounter.WithLabelValues("CreateApplicationUserLanguage").Inc()
	}
	return nil, nil
}

func (r *mutationResolver) DeleteApplicationUserLanguage(ctx context.Context, userID string, userLanguage string) (*model.ApplicationUserLanguageList, error) {
	QueryCounter.WithLabelValues("DeleteApplicationUserLanguage").Inc()
	start := time.Now()
	startTimer := prometheus.NewTimer(prometheus.ObserverFunc(QueryTimer.WithLabelValues("DeleteApplicationUserLanguage").Set))
	defer func() {
		QueryHistogram.WithLabelValues("DeleteApplicationUserLanguage").Observe(time.Since(start).Seconds())
		startTimer.ObserveDuration()
	}()
	oldspan := trace.SpanFromContext(ctx)
	tracer := oldspan.TracerProvider().Tracer("DeleteApplicationUserLanguage")
	awsContext, span := tracer.Start(ctx, "DeleteApplicationUserLanguage")
	defer span.End()
	span.SetAttributes(attribute.String("userID", userID))
	span.SetAttributes(attribute.String("userLanguage", userLanguage))
	queryLog := &QueryLog{
		Name:    "DeleteApplicationUserLanguage",
		TraceId: oldspan.SpanContext().TraceID().String(),
		Arguments: map[string]interface{}{
			"userID":       userID,
			"userLanguage": userLanguage,
		},
	}
	ql, _ := json.Marshal(queryLog)
	fmt.Println(string(ql))

	cfg, err := config.LoadDefaultConfig(awsContext, AwsConfig)
	otelaws.AppendMiddlewares(&cfg.APIOptions)

	allowedServiceRoles := []string{"service-one"}
	allowedUserRoles := []string{"system-admin"}
	_allowed, currentLoggedInRole := middleware.RoleAllowed(ctx, allowedServiceRoles, allowedUserRoles)
	if !_allowed {
		QueryAuthFailureCounter.WithLabelValues("DeleteApplicationUserLanguage", currentLoggedInRole).Inc()
		err = errors.New("unauthorized role: " + currentLoggedInRole)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	if err == nil {
		db := dynamodb.NewFromConfig(cfg, DynamodbConfig)

		_, err = db.DeleteItem(awsContext, &dynamodb.DeleteItemInput{
			TableName: aws.String(utils.GetProcessedTableName("application-userLanguage")),
			Key: map[string]types.AttributeValue{
				"userId":       &types.AttributeValueMemberS{Value: userID},
				"userLanguage": &types.AttributeValueMemberS{Value: userLanguage},
			},
		})
		var result model.ApplicationUserLanguageList
		if err != nil {
			if strings.Contains(err.Error(), "ConditionalCheckFailedException") {
				err = errors.New("delete failed due to constraint mismatch")
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("DeleteApplicationUserLanguage").Inc()
			return &result, err
		}

	} else {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		QueryFailureCounter.WithLabelValues("DeleteApplicationUserLanguage").Inc()
	}
	return nil, nil
}

func (r *queryResolver) GetApplicationUser(ctx context.Context, userID string) (*model.ApplicationUserList, error) {
	QueryCounter.WithLabelValues("GetApplicationUser").Inc()
	start := time.Now()
	startTimer := prometheus.NewTimer(prometheus.ObserverFunc(QueryTimer.WithLabelValues("GetApplicationUser").Set))
	defer func() {
		QueryHistogram.WithLabelValues("GetApplicationUser").Observe(time.Since(start).Seconds())
		startTimer.ObserveDuration()
	}()
	oldspan := trace.SpanFromContext(ctx)
	tracer := oldspan.TracerProvider().Tracer("GetApplicationUser")
	awsContext, span := tracer.Start(ctx, "GetApplicationUser")
	defer span.End()
	span.SetAttributes(attribute.String("userID", userID))
	queryLog := &QueryLog{
		Name:    "GetApplicationUser",
		TraceId: oldspan.SpanContext().TraceID().String(),
		Arguments: map[string]interface{}{
			"userID": userID,
		},
	}
	ql, _ := json.Marshal(queryLog)
	fmt.Println(string(ql))

	cfg, err := config.LoadDefaultConfig(awsContext, AwsConfig)
	otelaws.AppendMiddlewares(&cfg.APIOptions)

	allowedServiceRoles := []string{"service-one"}
	allowedUserRoles := []string{"system-admin"}
	_allowed, currentLoggedInRole := middleware.RoleAllowed(ctx, allowedServiceRoles, allowedUserRoles)
	if !_allowed {
		QueryAuthFailureCounter.WithLabelValues("GetApplicationUser", currentLoggedInRole).Inc()
		err = errors.New("unauthorized role: " + currentLoggedInRole)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	if err == nil {
		db := dynamodb.NewFromConfig(cfg, DynamodbConfig)

		var result model.ApplicationUserList
		items := []model.ApplicationUser{}
		filterExpression := make([]string, 0)
		eav := make(map[string]types.AttributeValue)
		kce := []string{}

		eav[":userId"] = &types.AttributeValueMemberS{Value: userID}
		kce = append(kce, "userId=:userId")

		qi := &dynamodb.QueryInput{
			TableName:                 aws.String(utils.GetProcessedTableName("application-user")),
			KeyConditionExpression:    aws.String(strings.Join(kce, " and ")),
			FilterExpression:          aws.String(strings.Join(filterExpression, " and ")),
			ExpressionAttributeValues: eav,
		}
		if len(filterExpression) == 0 {
			qi.FilterExpression = nil
		}
		p := dynamodb.NewQueryPaginator(db, qi)
		var out *dynamodb.QueryOutput
		var err error
		for p.HasMorePages() {
			out, err = p.NextPage(awsContext)
			if err == nil {
				if out.Count > 0 {
					err = attributevalue.UnmarshalListOfMaps(out.Items, &items)
					if err != nil {
						break
					}
					for i := 0; i < len(items); i++ {
						result.Items = append(result.Items, &items[i])
					}
				}
			} else {
				break
			}
		}

		// start subquery Company
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.Company"]; ok {
			if len(result.Items) > 0 {
				Company := []model.ApplicationCompany{}
				CompanyIDMap := make(map[string][]string)
				ApplicationUserMap := make(map[string]*model.ApplicationUser)
				CompanyIDkeys := make([]map[string]types.AttributeValue, 0)
				for i := 0; i < len(result.Items); i++ {
					if result.Items[i].CompanyID != nil {
						ApplicationUserMap[result.Items[i].UserID] = result.Items[i]
						_, ok := CompanyIDMap[*result.Items[i].CompanyID]
						if !ok {
							CompanyIDMap[*result.Items[i].CompanyID] = make([]string, 0)
							CompanyIDkeys = append(CompanyIDkeys, map[string]types.AttributeValue{"companyId": &types.AttributeValueMemberS{Value: *result.Items[i].CompanyID}})
						}
						CompanyIDMap[*result.Items[i].CompanyID] = append(CompanyIDMap[*result.Items[i].CompanyID], result.Items[i].UserID)
					}
				}
				if len(CompanyIDkeys) > 0 {
					CompanyIDBatchGet, CompanyIDErr := db.BatchGetItem(awsContext, &dynamodb.BatchGetItemInput{
						RequestItems: map[string]types.KeysAndAttributes{
							utils.GetProcessedTableName("application-company"): {
								Keys: CompanyIDkeys,
							},
						},
					})
					if CompanyIDErr == nil {
						if len(CompanyIDBatchGet.Responses[utils.GetProcessedTableName("application-company")]) > 0 {
							err = attributevalue.UnmarshalListOfMaps(CompanyIDBatchGet.Responses[utils.GetProcessedTableName("application-company")], &Company)
							for i := 0; i < len(Company); i++ {
								for j := 0; j < len(CompanyIDMap[Company[i].CompanyID]); j++ {
									userID := CompanyIDMap[Company[i].CompanyID][j]
									if entry, ok := ApplicationUserMap[userID]; ok {
										entry.Company = &Company[i]
									}
								}
							}
						}
					} else {
						err = CompanyIDErr
					}
				}
			}
		}
		// end subquery Company

		// start subquery Languages
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.Languages"]; ok {
			if len(result.Items) > 0 {
				UserIDMap := make(map[string][]string)
				ApplicationUserMap := make(map[string]*model.ApplicationUser)
				for i := 0; i < len(result.Items); i++ {
					ApplicationUserMap[result.Items[i].UserID] = result.Items[i]
					_, ok := UserIDMap[result.Items[i].UserID]
					if !ok {
						UserIDMap[result.Items[i].UserID] = make([]string, 0)
						UserIDMap[result.Items[i].UserID] = append(UserIDMap[result.Items[i].UserID], result.Items[i].UserID)
						qieav := make(map[string]types.AttributeValue)
						qikce := []string{}
						qieav[":userId"] = &types.AttributeValueMemberS{Value: result.Items[i].UserID}
						qikce = append(qikce, "userId=:userId")
						qi := &dynamodb.QueryInput{
							TableName:                 aws.String(utils.GetProcessedTableName("application-userLanguage")),
							KeyConditionExpression:    aws.String(strings.Join(qikce, " and ")),
							ExpressionAttributeValues: qieav,
							ConsistentRead:            aws.Bool(true),
						}
						p := dynamodb.NewQueryPaginator(db, qi)
						var out *dynamodb.QueryOutput
						var err error
						for p.HasMorePages() {
							Languages := []model.ApplicationUserLanguage{}
							out, err = p.NextPage(awsContext)
							if err == nil {
								if out.Count > 0 {
									err = attributevalue.UnmarshalListOfMaps(out.Items, &Languages)
									if err != nil {
										break
									}
									for j := 0; j < len(Languages); j++ {
										ApplicationUserMap[result.Items[i].UserID].Languages = append(ApplicationUserMap[result.Items[i].UserID].Languages, &Languages[j])
									}
								} else {
									ApplicationUserMap[result.Items[i].UserID].Languages = make([]*model.ApplicationUserLanguage, 0)
								}
							} else {
								break
							}
						}
					}
				}
			}
		}

		// start subquery CustomData
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.CustomData"]; ok {
			if len(result.Items) > 0 {
				custom.GetCustomData(ctx, GetPreloads(ctx), &result)
			}
		}
		// end subquery CustomData

		span.AddEvent("results", trace.WithAttributes(attribute.Int("count", len(result.Items))))

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("GetApplicationUser").Inc()
		}
		return &result, err

	} else {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		QueryFailureCounter.WithLabelValues("GetApplicationUser").Inc()
	}
	return nil, nil
}

func (r *queryResolver) SearchApplicationUser(ctx context.Context, userName string) (*model.ApplicationUserList, error) {
	QueryCounter.WithLabelValues("SearchApplicationUser").Inc()
	start := time.Now()
	startTimer := prometheus.NewTimer(prometheus.ObserverFunc(QueryTimer.WithLabelValues("SearchApplicationUser").Set))
	defer func() {
		QueryHistogram.WithLabelValues("SearchApplicationUser").Observe(time.Since(start).Seconds())
		startTimer.ObserveDuration()
	}()
	oldspan := trace.SpanFromContext(ctx)
	tracer := oldspan.TracerProvider().Tracer("SearchApplicationUser")
	awsContext, span := tracer.Start(ctx, "SearchApplicationUser")
	defer span.End()
	span.SetAttributes(attribute.String("userName", userName))
	queryLog := &QueryLog{
		Name:    "SearchApplicationUser",
		TraceId: oldspan.SpanContext().TraceID().String(),
		Arguments: map[string]interface{}{
			"userName": userName,
		},
	}
	ql, _ := json.Marshal(queryLog)
	fmt.Println(string(ql))

	cfg, err := config.LoadDefaultConfig(awsContext, AwsConfig)
	otelaws.AppendMiddlewares(&cfg.APIOptions)

	allowedServiceRoles := []string{"service-one"}
	allowedUserRoles := []string{"system-admin"}
	_allowed, currentLoggedInRole := middleware.RoleAllowed(ctx, allowedServiceRoles, allowedUserRoles)
	if !_allowed {
		QueryAuthFailureCounter.WithLabelValues("SearchApplicationUser", currentLoggedInRole).Inc()
		err = errors.New("unauthorized role: " + currentLoggedInRole)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	if err == nil {
		db := dynamodb.NewFromConfig(cfg, DynamodbConfig)

		var result model.ApplicationUserList
		items := []model.ApplicationUser{}
		filterExpression := make([]string, 0)
		eav := make(map[string]types.AttributeValue)
		kce := []string{}

		eav[":userName"] = &types.AttributeValueMemberS{Value: userName}
		kce = append(kce, "userName=:userName")

		qi := &dynamodb.QueryInput{
			TableName:                 aws.String(utils.GetProcessedTableName("application-user")),
			IndexName:                 aws.String("userName-index"),
			KeyConditionExpression:    aws.String(strings.Join(kce, " and ")),
			FilterExpression:          aws.String(strings.Join(filterExpression, " and ")),
			ExpressionAttributeValues: eav,
		}
		if len(filterExpression) == 0 {
			qi.FilterExpression = nil
		}
		p := dynamodb.NewQueryPaginator(db, qi)
		var out *dynamodb.QueryOutput
		var err error
		for p.HasMorePages() {
			out, err = p.NextPage(awsContext)
			if err == nil {
				if out.Count > 0 {
					err = attributevalue.UnmarshalListOfMaps(out.Items, &items)
					if err != nil {
						break
					}
					for i := 0; i < len(items); i++ {
						result.Items = append(result.Items, &items[i])
					}
				}
			} else {
				break
			}
		}

		// start subquery Company
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.Company"]; ok {
			if len(result.Items) > 0 {
				Company := []model.ApplicationCompany{}
				CompanyIDMap := make(map[string][]string)
				ApplicationUserMap := make(map[string]*model.ApplicationUser)
				CompanyIDkeys := make([]map[string]types.AttributeValue, 0)
				for i := 0; i < len(result.Items); i++ {
					if result.Items[i].CompanyID != nil {
						ApplicationUserMap[result.Items[i].UserID] = result.Items[i]
						_, ok := CompanyIDMap[*result.Items[i].CompanyID]
						if !ok {
							CompanyIDMap[*result.Items[i].CompanyID] = make([]string, 0)
							CompanyIDkeys = append(CompanyIDkeys, map[string]types.AttributeValue{"companyId": &types.AttributeValueMemberS{Value: *result.Items[i].CompanyID}})
						}
						CompanyIDMap[*result.Items[i].CompanyID] = append(CompanyIDMap[*result.Items[i].CompanyID], result.Items[i].UserID)
					}
				}
				if len(CompanyIDkeys) > 0 {
					CompanyIDBatchGet, CompanyIDErr := db.BatchGetItem(awsContext, &dynamodb.BatchGetItemInput{
						RequestItems: map[string]types.KeysAndAttributes{
							utils.GetProcessedTableName("application-company"): {
								Keys: CompanyIDkeys,
							},
						},
					})
					if CompanyIDErr == nil {
						if len(CompanyIDBatchGet.Responses[utils.GetProcessedTableName("application-company")]) > 0 {
							err = attributevalue.UnmarshalListOfMaps(CompanyIDBatchGet.Responses[utils.GetProcessedTableName("application-company")], &Company)
							for i := 0; i < len(Company); i++ {
								for j := 0; j < len(CompanyIDMap[Company[i].CompanyID]); j++ {
									userID := CompanyIDMap[Company[i].CompanyID][j]
									if entry, ok := ApplicationUserMap[userID]; ok {
										entry.Company = &Company[i]
									}
								}
							}
						}
					} else {
						err = CompanyIDErr
					}
				}
			}
		}
		// end subquery Company

		// start subquery Languages
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.Languages"]; ok {
			if len(result.Items) > 0 {
				UserIDMap := make(map[string][]string)
				ApplicationUserMap := make(map[string]*model.ApplicationUser)
				for i := 0; i < len(result.Items); i++ {
					ApplicationUserMap[result.Items[i].UserID] = result.Items[i]
					_, ok := UserIDMap[result.Items[i].UserID]
					if !ok {
						UserIDMap[result.Items[i].UserID] = make([]string, 0)
						UserIDMap[result.Items[i].UserID] = append(UserIDMap[result.Items[i].UserID], result.Items[i].UserID)
						qieav := make(map[string]types.AttributeValue)
						qikce := []string{}
						qieav[":userId"] = &types.AttributeValueMemberS{Value: result.Items[i].UserID}
						qikce = append(qikce, "userId=:userId")
						qi := &dynamodb.QueryInput{
							TableName:                 aws.String(utils.GetProcessedTableName("application-userLanguage")),
							KeyConditionExpression:    aws.String(strings.Join(qikce, " and ")),
							ExpressionAttributeValues: qieav,
							ConsistentRead:            aws.Bool(true),
						}
						p := dynamodb.NewQueryPaginator(db, qi)
						var out *dynamodb.QueryOutput
						var err error
						for p.HasMorePages() {
							Languages := []model.ApplicationUserLanguage{}
							out, err = p.NextPage(awsContext)
							if err == nil {
								if out.Count > 0 {
									err = attributevalue.UnmarshalListOfMaps(out.Items, &Languages)
									if err != nil {
										break
									}
									for j := 0; j < len(Languages); j++ {
										ApplicationUserMap[result.Items[i].UserID].Languages = append(ApplicationUserMap[result.Items[i].UserID].Languages, &Languages[j])
									}
								} else {
									ApplicationUserMap[result.Items[i].UserID].Languages = make([]*model.ApplicationUserLanguage, 0)
								}
							} else {
								break
							}
						}
					}
				}
			}
		}

		// start subquery CustomData
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.CustomData"]; ok {
			if len(result.Items) > 0 {
				custom.GetCustomData(ctx, GetPreloads(ctx), &result)
			}
		}
		// end subquery CustomData

		span.AddEvent("results", trace.WithAttributes(attribute.Int("count", len(result.Items))))

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("SearchApplicationUser").Inc()
		}
		return &result, err

	} else {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		QueryFailureCounter.WithLabelValues("SearchApplicationUser").Inc()
	}
	return nil, nil
}

func (r *queryResolver) ListApplicationCompany(ctx context.Context) (*model.ApplicationCompanyList, error) {
	QueryCounter.WithLabelValues("ListApplicationCompany").Inc()
	start := time.Now()
	startTimer := prometheus.NewTimer(prometheus.ObserverFunc(QueryTimer.WithLabelValues("ListApplicationCompany").Set))
	defer func() {
		QueryHistogram.WithLabelValues("ListApplicationCompany").Observe(time.Since(start).Seconds())
		startTimer.ObserveDuration()
	}()
	oldspan := trace.SpanFromContext(ctx)
	tracer := oldspan.TracerProvider().Tracer("ListApplicationCompany")
	awsContext, span := tracer.Start(ctx, "ListApplicationCompany")
	defer span.End()

	queryLog := &QueryLog{
		Name:      "ListApplicationCompany",
		TraceId:   oldspan.SpanContext().TraceID().String(),
		Arguments: map[string]interface{}{},
	}
	ql, _ := json.Marshal(queryLog)
	fmt.Println(string(ql))

	cfg, err := config.LoadDefaultConfig(awsContext, AwsConfig)
	otelaws.AppendMiddlewares(&cfg.APIOptions)

	allowedServiceRoles := []string{"service-one"}
	allowedUserRoles := []string{"system-admin"}
	_allowed, currentLoggedInRole := middleware.RoleAllowed(ctx, allowedServiceRoles, allowedUserRoles)
	if !_allowed {
		QueryAuthFailureCounter.WithLabelValues("ListApplicationCompany", currentLoggedInRole).Inc()
		err = errors.New("unauthorized role: " + currentLoggedInRole)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	if err == nil {
		db := dynamodb.NewFromConfig(cfg, DynamodbConfig)

		var result model.ApplicationCompanyList
		items := []model.ApplicationCompany{}
		filterExpression := make([]string, 0)
		eav := make(map[string]types.AttributeValue)

		si := &dynamodb.ScanInput{
			TableName:                 aws.String(utils.GetProcessedTableName("application-company")),
			FilterExpression:          aws.String(strings.Join(filterExpression, " and ")),
			ExpressionAttributeValues: eav,
		}
		if len(filterExpression) == 0 {
			si.FilterExpression = nil
		}
		if len(eav) == 0 {
			si.ExpressionAttributeValues = nil
		}
		p := dynamodb.NewScanPaginator(db, si)
		var out *dynamodb.ScanOutput
		var err error
		for p.HasMorePages() {
			out, err = p.NextPage(awsContext)
			if err == nil {
				if out.Count > 0 {
					err = attributevalue.UnmarshalListOfMaps(out.Items, &items)
					if err != nil {
						break
					}
					for i := 0; i < len(items); i++ {
						result.Items = append(result.Items, &items[i])
					}
				}
			} else {
				break
			}
		}

		span.AddEvent("results", trace.WithAttributes(attribute.Int("count", len(result.Items))))

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("ListApplicationCompany").Inc()
		}
		return &result, err

	} else {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		QueryFailureCounter.WithLabelValues("ListApplicationCompany").Inc()
	}
	return nil, nil
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
