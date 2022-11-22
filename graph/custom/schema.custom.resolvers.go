package custom

import (
	"context"

	"github.com/craftyc0der/gqlgen-dynamodb/graph/model"
)

func GetCustomData(
	ctx context.Context,
	preloads map[string]struct{},
	result *model.ApplicationUserList,
) (*model.ApplicationUserList, error) {
	returnDetails := make([]*model.ApplicationCustomData, 0)
	returnDetails = append(returnDetails, &model.ApplicationCustomData{
		Foo: "foo",
		Bar: "bar",
	})
	returnValue := &model.ApplicationCustomSource{
		Custom: returnDetails,
	}
	// loop over result and add returnValue to CustomData field
	for _, item := range result.Items {
		item.CustomData = returnValue
	}
	return result, nil
}
