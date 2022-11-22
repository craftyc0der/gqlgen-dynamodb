FROM amazon/dynamodb-local:latest
COPY --chown=dynamodblocal ./dynamo/shared-local-instance.db /home/dynamodblocal/data/shared-local-instance.db
CMD ["-jar", "DynamoDBLocal.jar", "-dbPath", "./data", "-sharedDb"]