package graph

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/99designs/gqlgen/client"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/craftyc0der/gqlgen-dynamodb/graph/model"
	"github.com/stretchr/testify/require"
)

func init() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err == nil {
		AwsConfig = func(o *config.LoadOptions) error {
			return nil
		}
		db := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
			o.EndpointResolver = dynamodb.EndpointResolverFromURL("http://localhost:8000")
		})
		_, err := db.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
			AttributeDefinitions: []types.AttributeDefinition{
				{
					AttributeName: aws.String("companyId"),
					AttributeType: types.ScalarAttributeTypeS,
				},
			},
			KeySchema: []types.KeySchemaElement{
				{
					AttributeName: aws.String("companyId"),
					KeyType:       types.KeyTypeHash,
				},
			},
			ProvisionedThroughput: &types.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(1),
				WriteCapacityUnits: aws.Int64(1),
			},
			TableName: aws.String("application-company"),
		})

		if err != nil {
			fmt.Println(err)
		}

		_, err = db.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
			AttributeDefinitions: []types.AttributeDefinition{
				{
					AttributeName: aws.String("userId"),
					AttributeType: types.ScalarAttributeTypeS,
				},
				{
					AttributeName: aws.String("userName"),
					AttributeType: types.ScalarAttributeTypeS,
				},
			},
			KeySchema: []types.KeySchemaElement{
				{
					AttributeName: aws.String("userId"),
					KeyType:       types.KeyTypeHash,
				},
				{
					AttributeName: aws.String("userName"),
					KeyType:       types.KeyTypeRange,
				},
			},
			ProvisionedThroughput: &types.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(1),
				WriteCapacityUnits: aws.Int64(1),
			},
			TableName: aws.String("application-user"),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				{
					IndexName: aws.String("userName-index"),
					KeySchema: []types.KeySchemaElement{
						{
							AttributeName: aws.String("userName"),
							KeyType:       types.KeyTypeHash,
						},
					},
					Projection: &types.Projection{
						ProjectionType: types.ProjectionTypeAll,
					},
					ProvisionedThroughput: &types.ProvisionedThroughput{
						ReadCapacityUnits:  aws.Int64(1),
						WriteCapacityUnits: aws.Int64(1),
					},
				},
			},
		})

		if err != nil {
			fmt.Println(err)
		}

		_, err = db.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
			AttributeDefinitions: []types.AttributeDefinition{
				{
					AttributeName: aws.String("userId"),
					AttributeType: types.ScalarAttributeTypeS,
				},
				{
					AttributeName: aws.String("userLanguage"),
					AttributeType: types.ScalarAttributeTypeS,
				},
			},
			KeySchema: []types.KeySchemaElement{
				{
					AttributeName: aws.String("userId"),
					KeyType:       types.KeyTypeHash,
				},
				{
					AttributeName: aws.String("userLanguage"),
					KeyType:       types.KeyTypeRange,
				},
			},
			ProvisionedThroughput: &types.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(1),
				WriteCapacityUnits: aws.Int64(1),
			},
			TableName: aws.String("application-userLanguage"),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				{
					IndexName: aws.String("userLanguage-index"),
					KeySchema: []types.KeySchemaElement{
						{
							AttributeName: aws.String("userLanguage"),
							KeyType:       types.KeyTypeHash,
						},
					},
					Projection: &types.Projection{
						ProjectionType: types.ProjectionTypeAll,
					},
					ProvisionedThroughput: &types.ProvisionedThroughput{
						ReadCapacityUnits:  aws.Int64(1),
						WriteCapacityUnits: aws.Int64(1),
					},
				},
			},
		})

		if err != nil {
			fmt.Println(err)
		}

		insertItem(db, "application-company", TestApplicationCompany1)
		insertItem(db, "application-company", TestApplicationCompany2)
		insertItem(db, "application-company", TestApplicationCompany3)
		insertItem(db, "application-company", TestApplicationCompany4)

		insertItem(db, "application-user", TestApplicationUser1)
		insertItem(db, "application-user", TestApplicationUser2)
		insertItem(db, "application-user", TestApplicationUser3)
		insertItem(db, "application-user", TestApplicationUser4)
		insertItem(db, "application-user", TestApplicationUser5)
		insertItem(db, "application-user", TestApplicationUser6)
		insertItem(db, "application-user", TestApplicationUser7)

		insertItem(db, "application-userLanguage", TestApplicationUserLanguage1)
		insertItem(db, "application-userLanguage", TestApplicationUserLanguage2)
		insertItem(db, "application-userLanguage", TestApplicationUserLanguage3)
		insertItem(db, "application-userLanguage", TestApplicationUserLanguage4)
		insertItem(db, "application-userLanguage", TestApplicationUserLanguage5)
		insertItem(db, "application-userLanguage", TestApplicationUserLanguage6)
		insertItem(db, "application-userLanguage", TestApplicationUserLanguage7)
		insertItem(db, "application-userLanguage", TestApplicationUserLanguage8)
		insertItem(db, "application-userLanguage", TestApplicationUserLanguage9)
	}
}

var getApplicationUserTests = []struct {
	userID string
	result []model.ApplicationUser
	ok     bool
}{
	{TestApplicationUser1.UserID, []model.ApplicationUser{*TestApplicationUser1}, true},
	{TestApplicationUser2.UserID, []model.ApplicationUser{*TestApplicationUser2}, true},
	{"none", []model.ApplicationUser{}, true},
}

func TestGetApplicationUser(t *testing.T) {
	AwsConfig = func(o *config.LoadOptions) error {
		return nil
	}

	DynamodbConfig = func(o *dynamodb.Options) {
		o.EndpointResolver = dynamodb.EndpointResolverFromURL("http://localhost:8000")
	}
	for _, tt := range getApplicationUserTests {
		c := client.New(test_handler)

		query := `{getApplicationUser( userID:"` + tt.userID + `")	{
			items {
				userID
				userName
				companyID
				company {
					companyID
					companyName
					createDate
				}
				createDate
				languages {
					userID
					userLanguage
				}
				customData {
					custom {
						foo
						bar
					}
				}
			}
		}
	}`
		var resp struct {
			GetApplicationUser struct {
				Items []model.ApplicationUser
			}
		}
		if tt.ok {
			c.MustPost(query, &resp)
			// compare lenth of items to tt.result
			if len(resp.GetApplicationUser.Items) != len(tt.result) {
				t.Errorf("expected %d items, got %d", len(tt.result), len(resp.GetApplicationUser.Items))
			}
			for i, item := range tt.result {
				require.Equal(t, item.UserID, resp.GetApplicationUser.Items[i].UserID)
				require.Equal(t, item.UserName, resp.GetApplicationUser.Items[i].UserName)
				require.Equal(t, item.CompanyID, resp.GetApplicationUser.Items[i].CompanyID)
			}
		} else {
			require.Equal(t, true, false, "this test should have failed")
		}
	}
}

var searchApplicationUserTests = []struct {
	userName string
	result   []model.ApplicationUser
	ok       bool
}{
	{TestApplicationUser1.UserName, []model.ApplicationUser{*TestApplicationUser1}, true},
	{TestApplicationUser2.UserName, []model.ApplicationUser{*TestApplicationUser2}, true},
	{"none", []model.ApplicationUser{}, true},
}

func TestSearchApplicationUser(t *testing.T) {
	AwsConfig = func(o *config.LoadOptions) error {
		return nil
	}

	DynamodbConfig = func(o *dynamodb.Options) {
		o.EndpointResolver = dynamodb.EndpointResolverFromURL("http://localhost:8000")
	}
	for _, tt := range searchApplicationUserTests {
		c := client.New(test_handler)

		query := `{searchApplicationUser( userName:"` + tt.userName + `")	{
			items {
				userID
				userName
				companyID
				company {
					companyID
					companyName
					createDate
				}
				createDate
				languages {
					userID
					userLanguage
				}
				customData {
					custom {
						foo
						bar
					}
				}
			}
		}
	}`
		var resp struct {
			SearchApplicationUser struct {
				Items []model.ApplicationUser
			}
		}
		if tt.ok {
			c.MustPost(query, &resp)
			// compare lenth of items to tt.result
			if len(resp.SearchApplicationUser.Items) != len(tt.result) {
				t.Errorf("expected %d items, got %d", len(tt.result), len(resp.SearchApplicationUser.Items))
			}
			for i, item := range tt.result {
				require.Equal(t, item.UserID, resp.SearchApplicationUser.Items[i].UserID)
				require.Equal(t, item.UserName, resp.SearchApplicationUser.Items[i].UserName)
				require.Equal(t, item.CompanyID, resp.SearchApplicationUser.Items[i].CompanyID)
			}
		} else {
			require.Equal(t, true, false, "this test should have failed")
		}
	}
}

var applicationUserToDelete = make([]string, 0)

var createApplicationUserTests = []struct {
	userName  string
	companyID string
	ok        bool
}{
	{"testuser6", TestApplicationCompany3.CompanyID, true},
}

func TestCreateApplicationUser(t *testing.T) {
	AwsConfig = func(o *config.LoadOptions) error {
		return nil
	}

	DynamodbConfig = func(o *dynamodb.Options) {
		o.EndpointResolver = dynamodb.EndpointResolverFromURL("http://localhost:8000")
	}
	for _, tt := range createApplicationUserTests {
		c := client.New(test_handler)
		query := `mutation {
			createApplicationUser(
					userName: "` + tt.userName + `"
					companyID: "` + tt.companyID + `"
			) {
				items {
					userID
					userName
					companyID
					company {
						companyID
						companyName
						createDate
					}
					createDate
					languages {
						userID
						userLanguage
					}
					customData {
						custom {
							foo
							bar
						}
					}
				}
			}
		}`
		var resp struct {
			CreateApplicationUser struct {
				Items []model.ApplicationUser
			}
		}
		if tt.ok {
			c.MustPost(query, &resp)
			// compare length of items to tt.result
			if len(resp.CreateApplicationUser.Items) != 1 {
				t.Errorf("expected %d items, got %d", 1, len(resp.CreateApplicationUser.Items))
			}
			require.Equal(t, tt.userName, resp.CreateApplicationUser.Items[0].UserName)
			require.Equal(t, tt.companyID, *resp.CreateApplicationUser.Items[0].CompanyID)
			applicationUserToDelete = append(applicationUserToDelete, resp.CreateApplicationUser.Items[0].UserID)
		} else {
			require.Equal(t, true, false, "this test should have failed")
		}
	}
}

var updateApplicationUserTests = []struct {
	userID    string
	userName  string
	companyID string
}{
	{TestApplicationUser1.UserID, TestApplicationUser1.UserName, TestApplicationCompany3.CompanyID},
	{TestApplicationUser1.UserID, TestApplicationUser1.UserName, TestApplicationCompany1.CompanyID},
}

func TestUpdateApplicationUser(t *testing.T) {
	AwsConfig = func(o *config.LoadOptions) error {
		return nil
	}

	DynamodbConfig = func(o *dynamodb.Options) {
		o.EndpointResolver = dynamodb.EndpointResolverFromURL("http://localhost:8000")
	}
	for _, tt := range updateApplicationUserTests {
		c := client.New(test_handler)
		query := `mutation {
			updateApplicationUser(
				userID: "` + tt.userID + `"
				userName: "` + tt.userName + `"
				companyID: "` + tt.companyID + `"
			) {
				items {
					userID
					userName
					companyID
					company {
						companyID
						companyName
						createDate
					}
					createDate
					languages {
						userID
						userLanguage
					}
					customData {
						custom {
							foo
							bar
						}
					}
				}
			}
		}`
		var resp struct {
			UpdateApplicationUser struct {
				Items []model.ApplicationUser
			}
		}
		c.MustPost(query, &resp)
		// compare length of items to tt.result
		if len(resp.UpdateApplicationUser.Items) != 1 {
			t.Errorf("expected %d items, got %d", 1, len(resp.UpdateApplicationUser.Items))
		}
		require.Equal(t, tt.userName, resp.UpdateApplicationUser.Items[0].UserName)
		require.Equal(t, tt.companyID, *resp.UpdateApplicationUser.Items[0].CompanyID)
	}
}

var createApplicationUserLanguageTests = []struct {
	userID       string
	userLanguage string
	ok           bool
}{
	{TestApplicationUser1.UserID, "latin", true},
	{TestApplicationUser1.UserID, "latin", false},
}

func TestCreateApplicationUserLanguage(t *testing.T) {
	AwsConfig = func(o *config.LoadOptions) error {
		return nil
	}

	DynamodbConfig = func(o *dynamodb.Options) {
		o.EndpointResolver = dynamodb.EndpointResolverFromURL("http://localhost:8000")
	}
	for _, tt := range createApplicationUserLanguageTests {
		c := client.New(test_handler)
		query := `mutation {
			createApplicationUserLanguage(
					userID: "` + tt.userID + `"
					userLanguage: "` + tt.userLanguage + `"
			) {
				items {
					userID
					userLanguage
				}
			}
		}`
		var resp struct {
			CreateApplicationUserLanguage struct {
				Items []model.ApplicationUserLanguage
			}
		}
		if tt.ok {
			c.MustPost(query, &resp)
			// compare length of items to tt.result
			if len(resp.CreateApplicationUserLanguage.Items) != 1 {
				t.Errorf("expected %d items, got %d", 1, len(resp.CreateApplicationUserLanguage.Items))
			}
			require.Equal(t, tt.userID, resp.CreateApplicationUserLanguage.Items[0].UserID)
			require.Equal(t, tt.userLanguage, resp.CreateApplicationUserLanguage.Items[0].UserLanguage)
		} else {
			err := c.Post(query, &resp)
			require.NotNil(t, err)
		}
	}
}

var deleteApplicationUserLanguageTests = []struct {
	userID       string
	userLanguage string
}{
	{TestApplicationUser1.UserID, "latin"},
}

func TestDeleteApplicationUserLanguage(t *testing.T) {
	AwsConfig = func(o *config.LoadOptions) error {
		return nil
	}

	DynamodbConfig = func(o *dynamodb.Options) {
		o.EndpointResolver = dynamodb.EndpointResolverFromURL("http://localhost:8000")
	}
	for _, tt := range deleteApplicationUserLanguageTests {
		c := client.New(test_handler)
		query := `mutation {
			deleteApplicationUserLanguage(
					userID: "` + tt.userID + `"
					userLanguage: "` + tt.userLanguage + `"
			) {
				items {
					userID
					userLanguage
				}
			}
		}`
		var resp struct {
			DeleteApplicationUserLanguage struct {
				Items []model.ApplicationUserLanguage
			}
		}
		c.MustPost(query, &resp)
		// compare length of items to tt.result
		if len(resp.DeleteApplicationUserLanguage.Items) != 0 {
			t.Errorf("expected %d items, got %d", 0, len(resp.DeleteApplicationUserLanguage.Items))
		}
	}
}

func getStringPointer(value string) *string {
	return &value
}

func getIntPointer(value int64) *int {
	retval := int(value)
	return &retval
}

var TestApplicationCompany1 = &model.ApplicationCompany{
	CompanyID:   GetUUID(),
	CompanyName: "DC Control Systems, LLC",
	CreateDate:  time.Now().Unix()*1000 + 10,
}

var TestApplicationCompany2 = &model.ApplicationCompany{
	CompanyID:   "10101010-0000-0000-0000-000000000000",
	CompanyName: "Amazon Web Services",
	CreateDate:  time.Now().Unix()*1000 + 10,
}

var TestApplicationCompany3 = &model.ApplicationCompany{
	CompanyID:   GetUUID(),
	CompanyName: "Data Services, Inc",
	CreateDate:  time.Now().Unix()*1000 + 10,
}

var TestApplicationCompany4 = &model.ApplicationCompany{
	CompanyID:   GetUUID(),
	CompanyName: "Alphabet, Inc",
	CreateDate:  time.Now().Unix()*1000 + 10,
}

var TestApplicationUser1 = &model.ApplicationUser{
	UserID:     "00000000-0000-0000-0000-000000000000",
	UserName:   "craftycoder",
	CompanyID:  getStringPointer(TestApplicationCompany1.CompanyID),
	CreateDate: time.Now().Unix()*1000 + 10,
}

var TestApplicationUser2 = &model.ApplicationUser{
	UserID:     GetUUID(),
	UserName:   "testuser1",
	CompanyID:  getStringPointer(TestApplicationCompany2.CompanyID),
	CreateDate: time.Now().Unix()*1000 + 10,
}

var TestApplicationUser3 = &model.ApplicationUser{
	UserID:     GetUUID(),
	UserName:   "testuser2",
	CompanyID:  getStringPointer(TestApplicationCompany2.CompanyID),
	CreateDate: time.Now().Unix()*1000 + 10,
}

var TestApplicationUser4 = &model.ApplicationUser{
	UserID:     GetUUID(),
	UserName:   "testuser3",
	CompanyID:  getStringPointer(TestApplicationCompany3.CompanyID),
	CreateDate: time.Now().Unix()*1000 + 10,
}

var TestApplicationUser5 = &model.ApplicationUser{
	UserID:     GetUUID(),
	UserName:   "testuser4",
	CompanyID:  getStringPointer(TestApplicationCompany3.CompanyID),
	CreateDate: time.Now().Unix()*1000 + 10,
}

var TestApplicationUser6 = &model.ApplicationUser{
	UserID:     GetUUID(),
	UserName:   "testuser5",
	CompanyID:  getStringPointer(TestApplicationCompany4.CompanyID),
	CreateDate: time.Now().Unix()*1000 + 10,
}

var TestApplicationUser7 = &model.ApplicationUser{
	UserID:     GetUUID(),
	UserName:   "testuser6",
	CompanyID:  getStringPointer(TestApplicationCompany4.CompanyID),
	CreateDate: time.Now().Unix()*1000 + 10,
}

var TestApplicationUserLanguage1 = &model.ApplicationUserLanguage{
	UserID:       TestApplicationUser1.UserID,
	UserLanguage: "rust",
}

var TestApplicationUserLanguage2 = &model.ApplicationUserLanguage{
	UserID:       TestApplicationUser1.UserID,
	UserLanguage: "golang",
}

var TestApplicationUserLanguage3 = &model.ApplicationUserLanguage{
	UserID:       TestApplicationUser1.UserID,
	UserLanguage: "english",
}

var TestApplicationUserLanguage4 = &model.ApplicationUserLanguage{
	UserID:       TestApplicationUser2.UserID,
	UserLanguage: "spanish",
}

var TestApplicationUserLanguage5 = &model.ApplicationUserLanguage{
	UserID:       TestApplicationUser3.UserID,
	UserLanguage: "italian",
}

var TestApplicationUserLanguage6 = &model.ApplicationUserLanguage{
	UserID:       TestApplicationUser4.UserID,
	UserLanguage: "latin",
}

var TestApplicationUserLanguage7 = &model.ApplicationUserLanguage{
	UserID:       TestApplicationUser5.UserID,
	UserLanguage: "polish",
}

var TestApplicationUserLanguage8 = &model.ApplicationUserLanguage{
	UserID:       TestApplicationUser6.UserID,
	UserLanguage: "german",
}

var TestApplicationUserLanguage9 = &model.ApplicationUserLanguage{
	UserID:       TestApplicationUser7.UserID,
	UserLanguage: "dutch",
}
