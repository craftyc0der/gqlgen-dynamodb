package main

import (
	"fmt"
	"os"

	"github.com/99designs/gqlgen/api"
	"github.com/99designs/gqlgen/codegen/config"
	"github.com/craftyc0der/gqlgen-dynamodb/plugin/directives"
	"github.com/craftyc0der/gqlgen-dynamodb/plugin/markdown"
	"github.com/craftyc0der/gqlgen-dynamodb/plugin/modelgen"
	"github.com/craftyc0der/gqlgen-dynamodb/plugin/resolvergen"
)

// this function is the entrypoint for `make generate``
func main() {
	cfg, err := config.LoadConfigFromDefaultLocations()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load config", err.Error())
		os.Exit(2)
	}

	err = api.Generate(cfg,
		// disable all default plugins
		api.NoPlugins(),
		// run our modelgen plugin
		// this creates the model structs
		api.AddPlugin(modelgen.New()),
		// run our directives plugin
		// this generates necessary functions for our resolver generator
		api.AddPlugin(directives.New("./graph/generated/directives.go", "directives")),
		// documentaion generation
		api.AddPlugin(markdown.New("./graphql.md", "resolvers", []string{"Application"})),
		// run our dynamodbgen plugin
		// this generates the DynamoDB resolvers
		api.AddPlugin(resolvergen.New()),
		// run it twice to get best go fmt results
		api.AddPlugin(resolvergen.New()),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(3)
	}
}
