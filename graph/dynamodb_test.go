package graph

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

var test_handler = GetDefaultHandler()

func init() {

}

func insertItem(db *dynamodb.Client, tableName string, item interface{}) {
	newItem, _ := attributevalue.MarshalMap(item)

	_, err := db.PutItem(context.TODO(), &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      newItem,
	})

	if err != nil {
		fmt.Println(err)
	}
}
