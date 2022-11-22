package resolvergen

import (
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/99designs/gqlgen/codegen"
	"github.com/99designs/gqlgen/codegen/config"
	"github.com/99designs/gqlgen/codegen/templates"
	"github.com/99designs/gqlgen/plugin"
	"github.com/craftyc0der/gqlgen-dynamodb/graph/generated"
	"github.com/craftyc0der/gqlgen-dynamodb/graph/model"
	"github.com/craftyc0der/gqlgen-dynamodb/internal/rewrite"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

//go:embed database.gotpl
var resolverTemplate string

func New() plugin.Plugin {
	return &Plugin{}
}

type Plugin struct{}

var _ plugin.CodeGenerator = &Plugin{}

func (m *Plugin) Name() string {
	return "database-resolver"
}

func (m *Plugin) GenerateCode(data *codegen.Data) error {
	if !data.Config.Resolver.IsDefined() {
		return nil
	}

	switch data.Config.Resolver.Layout {
	case config.LayoutSingleFile:
		return m.generateSingleFile(data)
	case config.LayoutFollowSchema:
		return m.generatePerSchema(data)
	}

	return nil
}

func (m *Plugin) generateSingleFile(data *codegen.Data) error {
	file := File{}

	if _, err := os.Stat(data.Config.Resolver.Filename); err == nil {
		// file already exists and we dont support updating resolvers with layout = single so just return
		return nil
	}

	for _, o := range data.Objects {
		if o.HasResolvers() {
			file.Objects = append(file.Objects, o)
		}
		for _, f := range o.Fields {
			if !f.IsResolver {
				continue
			}

			resolver := Resolver{o, f, "// foo", `panic("not implemented")`}
			file.Resolvers = append(file.Resolvers, &resolver)
		}
	}

	resolverBuild := &ResolverBuild{
		File:         &file,
		PackageName:  data.Config.Resolver.Package,
		ResolverType: data.Config.Resolver.Type,
		HasRoot:      true,
	}

	return templates.Render(templates.Options{
		PackageName: data.Config.Resolver.Package,
		FileNotice:  `// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.`,
		Filename:    data.Config.Resolver.Filename,
		Data:        resolverBuild,
		Packages:    data.Config.Packages,
		Template:    resolverTemplate,
	})
}

func (m *Plugin) generatePerSchema(data *codegen.Data) error {
	rewriter, err := rewrite.New(data.Config.Resolver.Dir())
	if err != nil {
		return err
	}

	files := map[string]*File{}

	objects := make(codegen.Objects, len(data.Objects)+len(data.Inputs))
	copy(objects, data.Objects)
	copy(objects[len(data.Objects):], data.Inputs)

	for _, o := range objects {
		if o.HasResolvers() {
			fn := gqlToResolverName(data.Config.Resolver.Dir(), o.Position.Src.Name, data.Config.Resolver.FilenameTemplate)
			if files[fn] == nil {
				files[fn] = &File{}
			}

			caser := cases.Title(language.English, cases.NoLower)
			rewriter.MarkStructCopied(templates.LcFirst(o.Name) + templates.UcFirst(data.Config.Resolver.Type))
			rewriter.GetMethodBody(data.Config.Resolver.Type, caser.String(o.Name))
			files[fn].Objects = append(files[fn].Objects, o)
		}
		for _, f := range o.Fields {
			if !f.IsResolver {
				continue
			}

			structName := templates.LcFirst(o.Name) + templates.UcFirst(data.Config.Resolver.Type)
			implementation := strings.TrimSpace(rewriter.GetMethodBody(structName, f.GoFieldName))
			comment := strings.TrimSpace(strings.TrimLeft(rewriter.GetMethodComment(structName, f.GoFieldName), `\`))
			// if the method body is empty, we don't need to generate a resolver
			if implementation == "" {
				// find Directive with name "dynamodbQuery" in o.Directives
				var dynamodbQuery *codegen.Directive
				var customResolver *codegen.Directive
				for _, d := range f.Directives {
					if d.Name == "dynamodbQuery" {
						dynamodbQuery = d
						break
					} else if d.Name == "customResolver" {
						customResolver = d
						break
					}
				}
				// create a resolver if the dynamodbQuery directive is found
				if dynamodbQuery != nil {
					implementation = generateDynamoDBQuery(o, f, dynamodbQuery)
				} else if customResolver != nil {
					implementation = generateCustomDynamoDBQuery(o, f, customResolver)
				} else {
					implementation = `panic(fmt.Errorf("not implemented"))`
				}
			}
			if comment == "" {
				comment = fmt.Sprintf("%v is the resolver for the %v field.", f.GoFieldName, f.Name)
			}

			resolver := Resolver{o, f, comment, implementation}
			fn := gqlToResolverName(data.Config.Resolver.Dir(), f.Position.Src.Name, data.Config.Resolver.FilenameTemplate)
			if files[fn] == nil {
				files[fn] = &File{}
			}

			files[fn].Resolvers = append(files[fn].Resolvers, &resolver)
		}
	}

	for filename, file := range files {
		file.imports = rewriter.ExistingImports(filename)
		file.RemainingSource = rewriter.RemainingSource(filename)
	}

	for filename, file := range files {
		resolverBuild := &ResolverBuild{
			File:         file,
			PackageName:  data.Config.Resolver.Package,
			ResolverType: data.Config.Resolver.Type,
		}

		err := templates.Render(templates.Options{
			PackageName: data.Config.Resolver.Package,
			FileNotice: `
				// This file will be automatically regenerated based on the schema, any resolver implementations
				// will be copied through when generating and any unknown code will be moved to the end.`,
			Filename: filename,
			Data:     resolverBuild,
			Packages: data.Config.Packages,
			Template: resolverTemplate,
		})
		if err != nil {
			return err
		}
	}

	if _, err := os.Stat(data.Config.Resolver.Filename); errors.Is(err, fs.ErrNotExist) {
		err := templates.Render(templates.Options{
			PackageName: data.Config.Resolver.Package,
			FileNotice: `
				// This file will not be regenerated automatically.
				//
				// It serves as dependency injection for your app, add any dependencies you require here.`,
			Template: `type {{.}} struct {}`,
			Filename: data.Config.Resolver.Filename,
			Data:     data.Config.Resolver.Type,
			Packages: data.Config.Packages,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// this is a helper function to generate the resolver for a customResolver directive
func generateCustomDynamoDBQuery(object *codegen.Object, field *codegen.Field, customResolverDirective *codegen.Directive) string {
	// details from the customResolver directive
	customResolver := generated.GetCustomResolver(customResolverDirective)
	// if this query has required roles, we parse them out of the directive
	requiredServiceRoles := make([]string, 0)
	requiredUserRoles := make([]string, 0)
	for _, d := range field.Directives {
		if d.Name == "authorizedRole" {
			authorizedRole := generated.GetAuthorizedRole(d)
			for _, role := range authorizedRole.ServiceRoles {
				requiredServiceRoles = append(requiredServiceRoles, fmt.Sprintf("\"%s\"", role))
			}
			for _, role := range authorizedRole.UserRoles {
				requiredUserRoles = append(requiredUserRoles, fmt.Sprintf("\"%s\"", role))
			}
			break
		}
	}
	// build the output implementation
	query := `
	QueryCounter.WithLabelValues("@@GoFieldName@@").Inc()
	start := time.Now()
	startTimer := prometheus.NewTimer(prometheus.ObserverFunc(QueryTimer.WithLabelValues("@@GoFieldName@@").Set))
	defer func() {
		QueryHistogram.WithLabelValues("@@GoFieldName@@").Observe(time.Since(start).Seconds())
		startTimer.ObserveDuration()
	}()
	oldspan := trace.SpanFromContext(ctx)
	tracer := oldspan.TracerProvider().Tracer("@@GoFieldName@@")
	awsContext, span := tracer.Start(ctx, "@@GoFieldName@@")
	defer span.End()
	@@SpanAttributes@@
	queryLog := &QueryLog{
		Name:    "@@GoFieldName@@",
		TraceId: oldspan.SpanContext().TraceID().String(),
		Arguments: map[string]interface{}{
			@@KvArgs@@
		},
	}
	ql, _ := json.Marshal(queryLog)
	fmt.Println(string(ql))
	`
	kvArgs := make([]string, 0)
	spanAttributes := make([]string, 0)
	for _, arg := range field.Args {
		kvArgs = append(kvArgs, fmt.Sprintf("\"%s\": %s,", arg.Name, arg.Name))
		if arg.TypeReference.IsPtr() {
			spanAttributes = append(spanAttributes, fmt.Sprintf("if %s != nil {", arg.Name))
			if arg.TypeReference.Definition.Name == "String" && !arg.TypeReference.IsSlice() {
				spanAttributes = append(spanAttributes, fmt.Sprintf("span.SetAttributes(attribute.String(\"%s\", *%s))", arg.Name, arg.Name))
			} else if arg.TypeReference.Definition.Name == "Int" && !arg.TypeReference.IsSlice() {
				spanAttributes = append(spanAttributes, fmt.Sprintf("span.SetAttributes(attribute.String(\"%s\", fmt.Sprintf(\"%%d\", *%s)))", arg.Name, arg.Name))
			} else {
				spanAttributes = append(spanAttributes, fmt.Sprintf("__%s, _err := json.Marshal(%s)\nif _err == nil {\nspan.SetAttributes(attribute.String(\"%s\", string(__%s)))\n}", arg.Name, arg.Name, arg.Name, arg.Name))
			}
			spanAttributes = append(spanAttributes, "}")
		} else {
			if arg.TypeReference.Definition.Name == "String" && !arg.TypeReference.IsSlice() {
				spanAttributes = append(spanAttributes, fmt.Sprintf("span.SetAttributes(attribute.String(\"%s\", %s))", arg.Name, arg.Name))
			} else if arg.TypeReference.Definition.Name == "Int" && !arg.TypeReference.IsSlice() {
				spanAttributes = append(spanAttributes, fmt.Sprintf("span.SetAttributes(attribute.String(\"%s\", fmt.Sprintf(\"%%d\", %s)))", arg.Name, arg.Name))
			} else {
				spanAttributes = append(spanAttributes, fmt.Sprintf("__%s, _err := json.Marshal(%s)\nif _err == nil {\nspan.SetAttributes(attribute.String(\"%s\", string(__%s)))\n}", arg.Name, arg.Name, arg.Name, arg.Name))
			}
		}
	}
	query = strings.ReplaceAll(query, "@@KvArgs@@", strings.Join(kvArgs, "\n"))
	query = strings.ReplaceAll(query, "@@SpanAttributes@@", strings.Join(spanAttributes, "\n"))
	query += `
			cfg, err := config.LoadDefaultConfig(awsContext, AwsConfig)
			otelaws.AppendMiddlewares(&cfg.APIOptions, otelaws.WithTracerProvider(oldspan.TracerProvider()))
	`
	if len(requiredServiceRoles) > 0 || len(requiredUserRoles) > 0 {
		query += `
			allowedServiceRoles := []string{@@requiredServiceRoles@@}
			allowedUserRoles := []string{@@requiredUserRoles@@}
			_allowed, currentLoggedInRole := middleware.RoleAllowed(ctx, allowedServiceRoles, allowedUserRoles)
			if !_allowed {
				QueryAuthFailureCounter.WithLabelValues("@@GoFieldName@@", currentLoggedInRole).Inc()
				err = errors.New("unauthorized role: " + currentLoggedInRole)
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}
		`
		query = strings.ReplaceAll(query, "@@requiredServiceRoles@@", strings.Join(requiredServiceRoles, ","))
		query = strings.ReplaceAll(query, "@@requiredUserRoles@@", strings.Join(requiredUserRoles, ","))
	}
	query += `
			if err == nil {
				db := dynamodb.NewFromConfig(cfg, DynamodbConfig)
				return @@customResolverName@@(ctx, GetPreloads(ctx), db, @@fields@@)
	`
	args := make([]string, 0)
	// loop over field.Args and extract VarName into args
	for _, arg := range field.Args {
		args = append(args, arg.VarName)
	}
	query = strings.ReplaceAll(query, "@@customResolverName@@", customResolver.Package+"."+customResolver.Function)
	query = strings.ReplaceAll(query, "@@fields@@", strings.Join(args, ", "))
	query += `
			} else {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
			}
			return nil, nil
	`
	query = strings.ReplaceAll(query, "@@GoFieldName@@", field.GoFieldName)
	return query
}

// this is a helper function to generate the resolver for a dynamodbQuery directive
func generateDynamoDBQuery(object *codegen.Object, field *codegen.Field, dynamodbQuery *codegen.Directive) string {
	// details from the dynamodbQuery directive
	dynamoDBQuery := generated.GetDynamodbQuery(dynamodbQuery)

	// map to store all the fields from the output struct
	allColumns := make(map[string]generated.Directive_DynamodbColumn)
	allDynamoDBSubqueries := make(map[string]generated.Directive_DynamodbSubquery)
	allCustomSubqueries := make(map[string]generated.Directive_CustomSubquery)

	// required arguments
	argumentsRequired := make(map[string]bool)

	// required output columns
	outputColumnRequired := make(map[string]bool)

	// columns used as arguments
	columns := make(map[string]generated.Directive_DynamodbColumn)

	// any filters passed in
	stringFilters := make(map[string]generated.Directive_DynamodbColumn)
	intFilters := make(map[string]generated.Directive_DynamodbColumn)
	floatFilters := make(map[string]generated.Directive_DynamodbColumn)
	boolFilters := make(map[string]generated.Directive_DynamodbColumn)

	// any filters passed in
	stringKeyFilters := make(map[string]generated.Directive_DynamodbColumn)
	intKeyFilters := make(map[string]generated.Directive_DynamodbColumn)
	floatKeyFilters := make(map[string]generated.Directive_DynamodbColumn)
	boolKeyFilters := make(map[string]generated.Directive_DynamodbColumn)

	// columns that need to have hashes calculated
	hashes := make(map[string]generated.Directive_Hash)

	// columns that need to have timestamp calculated
	timestamps := make(map[string]generated.Directive_Timestamp)

	// columns that have mutationConditions
	mutationConditions := make(map[string]string)

	// columns that have arrayInputUnique conditions
	arrayInputUniqueConditions := make(map[string]generated.Directive_ArrayInputUnique)

	// columns that need to have uuid calculated
	uuids := make(map[string]bool)

	// columns that need to have uuid calculated
	defaultValues := make(map[string]generated.Directive_DefaultValue)

	// primary key fields (these need special handling)
	var hashKey generated.Directive_DynamodbColumn
	var rangeKey generated.Directive_DynamodbColumn

	// if this query has required roles, we parse them out of the directive
	requiredServiceRoles := make([]string, 0)
	requiredUserRoles := make([]string, 0)
	for _, d := range field.Directives {
		if d.Name == "authorizedRole" {
			authorizedRole := generated.GetAuthorizedRole(d)
			for _, role := range authorizedRole.ServiceRoles {
				requiredServiceRoles = append(requiredServiceRoles, fmt.Sprintf("\"%s\"", role))
			}
			for _, role := range authorizedRole.UserRoles {
				requiredUserRoles = append(requiredUserRoles, fmt.Sprintf("\"%s\"", role))
			}
			break
		}
	}

	// class the query returns
	outputClass := field.TypeReference.Definition.Name
	if field.TypeReference.Definition.Fields.ForName("items") != nil {
		outputClass = field.TypeReference.Definition.Fields.ForName("items").Type.Elem.NamedType
	}
	// reflection type of the output class
	// function is created during the code generation
	outputType := model.Types[outputClass]

	if outputType != nil {
		// Iterate over all available fields and read the tag value
		for i := 0; i < outputType.NumField(); i++ {
			// Get the field, returns https://golang.org/pkg/reflect/#StructField
			field := outputType.Field(i)

			// get the field tag value
			// get database column details
			tag := field.Tag.Get("dynamodbColumn")
			var column = generated.ExtractDynamodbColumn(tag)
			allColumns[strings.ToLower(field.Name)] = column

			// get dynamodb subquery details
			tag = field.Tag.Get("dynamodbSubquery")
			var dynamoSubquery = generated.ExtractDynamodbSubquery(tag)
			if dynamoSubquery.HashKeyFieldName != "" {
				allDynamoDBSubqueries[ToTitleCase(field.Name)] = dynamoSubquery
			}

			// get custom subquery details
			tag = field.Tag.Get("customSubquery")
			var customSubquery = generated.ExtractCustomSubquery(tag)
			if customSubquery.Package != "" && customSubquery.Function != "" {
				allCustomSubqueries[ToTitleCase(field.Name)] = customSubquery
			}

			// get the hash details
			tag = field.Tag.Get("hash")
			var hash = generated.ExtractHash(tag)
			if hash.FieldName != "" {
				hashes[strings.ToLower(field.Name)] = hash
				columns[strings.ToLower(field.Name)] = column
			}

			// get the defaultValue details
			tag = field.Tag.Get("defaultValue")
			if tag != "" {
				var defaultValue = generated.ExtractDefaultValue(tag)
				defaultValues[strings.ToLower(field.Name)] = defaultValue
				if dynamoDBQuery.Insert {
					columns[strings.ToLower(field.Name)] = column
					argumentsRequired[strings.ToLower(field.Name)] = true
				}
			}

			// get the uuid details
			tag = field.Tag.Get("uuid")
			if tag != "" {
				var uuid = generated.ExtractUuid(tag)
				uuids[strings.ToLower(field.Name)] = true
				columns[strings.ToLower(field.Name)] = column
				if dynamoDBQuery.Insert {
					if uuid.HashKey {
						hashKey = column
						argumentsRequired[strings.ToLower(field.Name)] = true
					}
				}
			}

			// get the timestamp details
			tag = field.Tag.Get("timestamp")
			if tag != "" {
				var timestamp = generated.ExtractTimestamp(tag)
				timestamps[strings.ToLower(field.Name)] = timestamp
				if dynamoDBQuery.Insert {
					columns[strings.ToLower(field.Name)] = column
					argumentsRequired[strings.ToLower(field.Name)] = true
				}
			}

			// if field type is a pointer set corresponding value of outputColumnRequired to false
			if field.Type.Kind() == reflect.Ptr {
				outputColumnRequired[strings.ToLower(field.Name)] = false
			} else {
				outputColumnRequired[strings.ToLower(field.Name)] = true
			}
		}
	}

	for _, arg := range field.Args {
		hashKeyFound := false
		rangeKeyFound := false

		// find the primary keys
		for _, d := range arg.Directives {
			if d.Name == "dynamodbHashKey" {
				hashKeyFound = true
			}
			if d.Name == "dynamodbRangeKey" {
				rangeKeyFound = true
			}
			if d.Name == "mutationCondition" {
				//loop over Args, if VarName == "expression" then get the value
				for _, d_arg := range d.Args {
					if d_arg.Name == "expression" {
						mutationConditions[strings.ToLower(arg.Name)] = fmt.Sprintf("%v", d_arg.Value)
					}
				}
			}
			if d.Name == "arrayInputUnique" {
				//loop over Args, if VarName == "fieldName" then get the value
				val := &generated.Directive_ArrayInputUnique{}
				for _, d_arg := range d.Args {
					if d_arg.Name == "fieldName" {
						val.FieldName = fmt.Sprintf("%v", d_arg.Value)
					}
					if d_arg.Name == "exceptionRegex" {
						if d_arg.Value != nil {
							val.ExceptionRegex = fmt.Sprintf("%v", d_arg.Value)
						}
					}
				}
				arrayInputUniqueConditions[strings.ToLower(arg.Name)] = *val
			}
		}
		if hashKeyFound {
			hashKey = allColumns[strings.ToLower(arg.Name)]
		}
		if rangeKeyFound {
			rangeKey = allColumns[strings.ToLower(arg.Name)]
		}

		// if the query has an argument that matches a column name, add it to the columns
		if val, ok := allColumns[strings.ToLower(arg.Name)]; ok {
			columns[strings.ToLower(arg.Name)] = val
		}

		// identify required columns by checking if the class is a pointer
		if !argumentsRequired[strings.ToLower(arg.Name)] && strings.HasPrefix(arg.TypeReference.GO.String(), "*") {
			argumentsRequired[strings.ToLower(arg.Name)] = false
		} else {
			argumentsRequired[strings.ToLower(arg.Name)] = true
		}

		// find the filters
		if arg.TypeReference.Definition.Name == "TableStringFilterInput" {
			if val, ok := allColumns[strings.ToLower(arg.Name)]; ok {
				stringFilters[strings.ToLower(arg.Name)] = val
			}
		}
		if arg.TypeReference.Definition.Name == "TableIntFilterInput" {
			if val, ok := allColumns[strings.ToLower(arg.Name)]; ok {
				intFilters[strings.ToLower(arg.Name)] = val
			}
		}
		if arg.TypeReference.Definition.Name == "TableFloatFilterInput" {
			if val, ok := allColumns[strings.ToLower(arg.Name)]; ok {
				floatFilters[strings.ToLower(arg.Name)] = val
			}
		}
		if arg.TypeReference.Definition.Name == "TableBooleanFilterInput" {
			if val, ok := allColumns[strings.ToLower(arg.Name)]; ok {
				boolFilters[strings.ToLower(arg.Name)] = val
			}
		}

		// find the key filters
		if arg.TypeReference.Definition.Name == "TableStringKeyInput" {
			if val, ok := allColumns[strings.ToLower(arg.Name)]; ok {
				stringKeyFilters[strings.ToLower(arg.Name)] = val
			}
		}
		if arg.TypeReference.Definition.Name == "TableIntKeyInput" {
			if val, ok := allColumns[strings.ToLower(arg.Name)]; ok {
				intKeyFilters[strings.ToLower(arg.Name)] = val
			}
		}
		if arg.TypeReference.Definition.Name == "TableFloatKeyInput" {
			if val, ok := allColumns[strings.ToLower(arg.Name)]; ok {
				floatKeyFilters[strings.ToLower(arg.Name)] = val
			}
		}
		if arg.TypeReference.Definition.Name == "TableBooleanKeyInput" {
			if val, ok := allColumns[strings.ToLower(arg.Name)]; ok {
				boolKeyFilters[strings.ToLower(arg.Name)] = val
			}
		}
	}

	// build the output implementation
	query := `
			QueryCounter.WithLabelValues("@@GoFieldName@@").Inc()
			start := time.Now()
			startTimer := prometheus.NewTimer(prometheus.ObserverFunc(QueryTimer.WithLabelValues("@@GoFieldName@@").Set))
			defer func() {
				QueryHistogram.WithLabelValues("@@GoFieldName@@").Observe(time.Since(start).Seconds())
				startTimer.ObserveDuration()
			}()
			oldspan := trace.SpanFromContext(ctx)
			tracer := oldspan.TracerProvider().Tracer("@@GoFieldName@@")
			awsContext, span := tracer.Start(ctx, "@@GoFieldName@@")
			defer span.End()
			@@SpanAttributes@@
			queryLog := &QueryLog{
				Name:    "@@GoFieldName@@",
				TraceId: oldspan.SpanContext().TraceID().String(),
				Arguments: map[string]interface{}{
					@@KvArgs@@
				},
			}
			ql, _ := json.Marshal(queryLog)
			fmt.Println(string(ql))
	`
	kvArgs := make([]string, 0)
	spanAttributes := make([]string, 0)
	for _, arg := range field.Args {
		kvArgs = append(kvArgs, fmt.Sprintf("\"%s\": %s,", arg.Name, arg.Name))
		if arg.TypeReference.IsPtr() {
			spanAttributes = append(spanAttributes, fmt.Sprintf("if %s != nil {", arg.Name))
			if arg.TypeReference.Definition.Name == "String" && !arg.TypeReference.IsSlice() {
				spanAttributes = append(spanAttributes, fmt.Sprintf("span.SetAttributes(attribute.String(\"%s\", *%s))", arg.Name, arg.Name))
			} else if arg.TypeReference.Definition.Name == "Int" && !arg.TypeReference.IsSlice() {
				spanAttributes = append(spanAttributes, fmt.Sprintf("span.SetAttributes(attribute.String(\"%s\", fmt.Sprintf(\"%%d\", *%s)))", arg.Name, arg.Name))
			} else {
				spanAttributes = append(spanAttributes, fmt.Sprintf("__%s, _err := json.Marshal(%s)\nif _err == nil {\nspan.SetAttributes(attribute.String(\"%s\", string(__%s)))\n}", arg.Name, arg.Name, arg.Name, arg.Name))
			}
			spanAttributes = append(spanAttributes, "}")
		} else {
			if arg.TypeReference.Definition.Name == "String" && !arg.TypeReference.IsSlice() {
				spanAttributes = append(spanAttributes, fmt.Sprintf("span.SetAttributes(attribute.String(\"%s\", %s))", arg.Name, arg.Name))
			} else if arg.TypeReference.Definition.Name == "Int" && !arg.TypeReference.IsSlice() {
				spanAttributes = append(spanAttributes, fmt.Sprintf("span.SetAttributes(attribute.String(\"%s\", fmt.Sprintf(\"%%d\", %s)))", arg.Name, arg.Name))
			} else {
				spanAttributes = append(spanAttributes, fmt.Sprintf("__%s, _err := json.Marshal(%s)\nif _err == nil {\nspan.SetAttributes(attribute.String(\"%s\", string(__%s)))\n}", arg.Name, arg.Name, arg.Name, arg.Name))
			}
		}
	}
	query = strings.ReplaceAll(query, "@@KvArgs@@", strings.Join(kvArgs, "\n"))
	query = strings.ReplaceAll(query, "@@SpanAttributes@@", strings.Join(spanAttributes, "\n"))
	query += `
			cfg, err := config.LoadDefaultConfig(awsContext, AwsConfig)
			otelaws.AppendMiddlewares(&cfg.APIOptions)
	`
	if len(requiredServiceRoles) > 0 || len(requiredUserRoles) > 0 {
		query += `
			allowedServiceRoles := []string{@@requiredServiceRoles@@}
			allowedUserRoles := []string{@@requiredUserRoles@@}
			_allowed, currentLoggedInRole := middleware.RoleAllowed(ctx, allowedServiceRoles, allowedUserRoles)
			if !_allowed {
				QueryAuthFailureCounter.WithLabelValues("@@GoFieldName@@", currentLoggedInRole).Inc()
				err = errors.New("unauthorized role: " + currentLoggedInRole)
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
			}
		`
		query = strings.ReplaceAll(query, "@@requiredServiceRoles@@", strings.Join(requiredServiceRoles, ","))
		query = strings.ReplaceAll(query, "@@requiredUserRoles@@", strings.Join(requiredUserRoles, ","))
	}
	query += `
			if err == nil {
				db := dynamodb.NewFromConfig(cfg, DynamodbConfig)
	`

	if dynamoDBQuery.Insert {
		// inserts
		if !dynamoDBQuery.Update {
			// TODO query for dbCompare columns and compare them to the values in the input
			// hash directive could have a previous calculated value that we set here and then compare in the insert
			// we likewise need to handle the immutable timestamp problem

			// for inserts that create their own UUID key we can skip this step
			skipCheck := false
			for key := range uuids {
				if key == strings.ToLower(hashKey.JsonName) {
					skipCheck = true
				}
			}
			if !skipCheck {
				query += generateGetItem(field, dynamoDBQuery, hashKey, rangeKey)
				query += `
					if currentItemExists {
				`
				if rangeKey.FieldName == "" {
					query += fmt.Sprintf("return nil, fmt.Errorf(\"%v already exists: %v\", %v)", hashKey.JsonName, `%v`, hashKey.JsonName)
				} else {
					query += fmt.Sprintf("return nil, fmt.Errorf(\"%v - %v already exists: %v - %v\", %v, %v)", hashKey.JsonName, rangeKey.JsonName, `%v`, `%v`, hashKey.JsonName, rangeKey.JsonName)
				}
				query += `
					}
				`
			}
		}
		if hashKey.FieldName == "" {
			panic("no hash key - cannot insert")
		}
		// output the insert query
		query += generateInsert(field, dynamoDBQuery, columns, allColumns, hashes, timestamps, defaultValues, uuids, argumentsRequired, arrayInputUniqueConditions)
		// query the database for record inserted and return it
		query += generateQuery(field, dynamoDBQuery, hashKey, rangeKey, stringFilters, intFilters, floatFilters, boolFilters, stringKeyFilters, intKeyFilters, floatKeyFilters, boolKeyFilters, argumentsRequired, outputColumnRequired, allColumns, allDynamoDBSubqueries, allCustomSubqueries)
	} else if dynamoDBQuery.Update && !dynamoDBQuery.Insert {
		// do updateItem query
		query += generateUpdate(field, dynamoDBQuery, hashKey, rangeKey, columns, allColumns, hashes, timestamps, uuids, argumentsRequired, mutationConditions, arrayInputUniqueConditions)
		query += generateQuery(field, dynamoDBQuery, hashKey, rangeKey, stringFilters, intFilters, floatFilters, boolFilters, stringKeyFilters, intKeyFilters, floatKeyFilters, boolKeyFilters, argumentsRequired, outputColumnRequired, allColumns, allDynamoDBSubqueries, allCustomSubqueries)
	} else if dynamoDBQuery.Delete {
		// deletes
		query += generateDelete(field, dynamoDBQuery, hashKey, rangeKey)
	} else {
		// queries
		// if there is no primary key do a table scan with filters only
		if hashKey.FieldName == "" {
			query += generateScan(field, dynamoDBQuery, stringFilters, intFilters, floatFilters, boolFilters, stringKeyFilters, intKeyFilters, floatKeyFilters, boolKeyFilters, outputColumnRequired, allColumns, allDynamoDBSubqueries, allCustomSubqueries)
		} else {
			if rangeKey.FieldName != "" {
				if !argumentsRequired[strings.ToLower(hashKey.JsonName)] && argumentsRequired[strings.ToLower(rangeKey.JsonName)] {
					panic("no hash key cannot be optional if range key is required")
				}
			}

			// check if hash key is required
			if !argumentsRequired[strings.ToLower(hashKey.JsonName)] {
				// add a table scan here if both keys are missing
				check := []string{fmt.Sprintf("%s == nil", hashKey.JsonName)}
				if rangeKey.FieldName != "" {
					check = append(check, fmt.Sprintf("%s == nil", rangeKey.JsonName))
				}
				query += fmt.Sprintf("if %s {\n", strings.Join(check, " && "))
				query += generateScan(field, dynamoDBQuery, stringFilters, intFilters, floatFilters, boolFilters, stringKeyFilters, intKeyFilters, floatKeyFilters, boolKeyFilters, outputColumnRequired, allColumns, allDynamoDBSubqueries, allCustomSubqueries)
				query += "} else {\n"
				if rangeKey.FieldName != "" {
					query += fmt.Sprintf("if %v == nil {\n", hashKey.JsonName)
					query += fmt.Sprintf("err = errors.New(\"%v cannot be nil if %v is not nil\")\n", hashKey.FieldName, rangeKey.FieldName)
					query += `
						span.RecordError(err)
						span.SetStatus(codes.Error, err.Error())
						QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
						return nil, err
					}
					`
				}
			}

			// output the query if a primary is possible
			query += generateQuery(field, dynamoDBQuery, hashKey, rangeKey, stringFilters, intFilters, floatFilters, boolFilters, stringKeyFilters, intKeyFilters, floatKeyFilters, boolKeyFilters, argumentsRequired, outputColumnRequired, allColumns, allDynamoDBSubqueries, allCustomSubqueries)

			// close off the if statement if a scan was also done
			if !argumentsRequired[strings.ToLower(hashKey.JsonName)] {
				query += "}\n"
			}
		}
	}
	query += `
			} else {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
			}
			return nil, nil
	`
	query = strings.ReplaceAll(query, "@@GoFieldName@@", field.GoFieldName)
	return query
}

// lower case the first letter of a string
func ToLowerCamelCase(s string) string {
	a := []rune(s)
	a[0] = unicode.ToLower(a[0])
	s = string(a)
	return s
}

func ToTitleCase(s string) string {
	caser := cases.Title(language.English, cases.NoLower)
	return caser.String(s)
}

// these generate functions output the dynamodb go code
// it is a string replacement system
func generateInsert(
	field *codegen.Field,
	dynamoDBQuery generated.Directive_DynamodbQuery,
	columns map[string]generated.Directive_DynamodbColumn,
	allColumns map[string]generated.Directive_DynamodbColumn,
	hashes map[string]generated.Directive_Hash,
	timestamps map[string]generated.Directive_Timestamp,
	defaultValues map[string]generated.Directive_DefaultValue,
	uuids map[string]bool,
	argumentsRequired map[string]bool,
	arrayInputUniqueConditions map[string]generated.Directive_ArrayInputUnique,
) string {
	outputClass := field.TypeReference.Definition.Fields.ForName("items").Type.Elem.NamedType
	returnClass := field.TypeReference.Definition.Name
	query := ""
	preQuery := ""

	uuidInits := ""
	for key := range uuids {
		argumentsRequired[key] = true
		uuidInits += fmt.Sprintf("%v := GetUUID()\n", ToLowerCamelCase(allColumns[key].JsonName))
	}

	if len(dynamoDBQuery.PreQueryFunction) > 0 {
		preQuery = fmt.Sprintf("@@fields@@, prqerr := %v.%v(ctx, GetPreloads(ctx), db, @@fields@@)\n", dynamoDBQuery.PreQueryPackage, dynamoDBQuery.PreQueryFunction)
		preQuery += "if prqerr != nil {\n"
		preQuery += "span.RecordError(prqerr)\n"
		preQuery += "span.SetStatus(codes.Error, prqerr.Error())\n"
		preQuery += "QueryFailureCounter.WithLabelValues(\"@@GoFieldName@@\").Inc()\n"
		preQuery += "return nil, prqerr\n"
		preQuery += "}\n"
		args := make([]string, 0)
		// loop over field.Args and extract VarName into args
		for _, arg := range field.Args {
			args = append(args, arg.VarName)
		}
		preQuery = strings.ReplaceAll(preQuery, "@@fields@@", strings.Join(args, ", "))
		preQuery = strings.ReplaceAll(preQuery, "@@GoFieldName@@", field.GoFieldName)
	}

	sortedTimestampKeys := make([]string, 0)
	for k := range timestamps {
		sortedTimestampKeys = append(sortedTimestampKeys, k)
	}
	sort.Strings(sortedTimestampKeys)
	timestampInits := ""
	for _, key := range sortedTimestampKeys {
		argumentsRequired[key] = true
		timestampInits += fmt.Sprintf("%v := int(time.Now().UnixMilli())\n", ToLowerCamelCase(allColumns[key].JsonName))
	}

	hashInits := ""
	for key, column := range hashes {
		argumentsRequired[key] = true
		hashInits += fmt.Sprintf("%v := fmt.Sprintf(\"%%x\", md5.Sum([]byte(%v)))\n", ToLowerCamelCase(allColumns[key].JsonName), column.FieldName)
	}

	listFields := ""
	sortedColumnsKeys := make([]string, 0)
	for k := range columns {
		sortedColumnsKeys = append(sortedColumnsKeys, k)
	}
	sort.Strings(sortedColumnsKeys)
	for _, key := range sortedColumnsKeys {
		column := columns[key]
		// TODO we will need to deal with optional lists here
		if column.FieldType == "L" {
			if val, ok := arrayInputUniqueConditions[strings.ToLower(column.JsonName)]; ok {
				listFields += fmt.Sprintf("// loop over %v and ensure there are no duplicate %v values\n", column.JsonName, val.FieldName)
				listFields += fmt.Sprintf("%vMap := make(map[string]bool)\n", val.FieldName)
				if val.ExceptionRegex != "" {
					listFields += fmt.Sprintf("%vException := regexp.MustCompile(`%v`)\n", strings.ToLower(column.JsonName), val.ExceptionRegex)
				}
				listFields += fmt.Sprintf("for i := 0; i < len(%v); i++ {\n", column.JsonName)
				listFields += fmt.Sprintf("if _, ok := %vMap[tags[i].%v]; ok {\n", val.FieldName, ToTitleCase(val.FieldName))
				listFields += fmt.Sprintf("err = errors.New(\"duplicate %v: \" + tags[i].%v)\n", val.FieldName, ToTitleCase(val.FieldName))
				listFields += "span.RecordError(err)\n"
				listFields += "span.SetStatus(codes.Error, err.Error())\n"
				listFields += fmt.Sprintf("QueryFailureCounter.WithLabelValues(\"%s\").Inc()\n", field.GoFieldName)
				listFields += "return nil, err\n}\n"
				if val.ExceptionRegex != "" {
					listFields += fmt.Sprintf("if !%vException.MatchString(tags[i].%v) {\n", strings.ToLower(column.JsonName), ToTitleCase(val.FieldName))
				}
				listFields += fmt.Sprintf("%vMap[tags[i].%v] = true\n", val.FieldName, ToTitleCase(val.FieldName))
				if val.ExceptionRegex != "" {
					listFields += "}\n"
				}
				listFields += "}\n"
			}
			listFields += fmt.Sprintf("%vList, _ := attributevalue.MarshalList(%v)\n", column.JsonName, column.JsonName)
		}
	}
	defaultValuesInits := ""
	for key, dv := range defaultValues {
		argumentsRequired[key] = true
		if dv.Variable != "" {
			defaultValuesInits += fmt.Sprintf("%v := %s\n", ToLowerCamelCase(allColumns[key].JsonName), dv.Variable)
		} else if dv.EnvVar != "" {
			defaultValuesInits += fmt.Sprintf("%v := os.Getenv(\"%s\")\n", ToLowerCamelCase(allColumns[key].JsonName), dv.EnvVar)
		} else if dv.Static != "" {
			defaultValuesInits += fmt.Sprintf("%v := %s)\n", ToLowerCamelCase(allColumns[key].JsonName), dv.Static)
		}
	}

	insertFields := "\"_updatedDate\": &types.AttributeValueMemberN{Value: strconv.Itoa(int(time.Now().UnixMilli()))},\n"
	optionalFields := ""
	for _, key := range sortedColumnsKeys {
		column := columns[key]
		if argumentsRequired[strings.ToLower(column.JsonName)] {
			if column.FieldType == "L" {
				insertFields += fmt.Sprintf("\"%v\":     &types.AttributeValueMember%v{Value: %vList},\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
			} else if column.FieldType == "N" {
				insertFields += fmt.Sprintf("\"%v\":     &types.AttributeValueMember%v{Value: strconv.Itoa(%v)},\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
			} else if column.FieldType == "M" {
				// optional fields is purposeful here. That gets inserted later on.
				optionalFields += fmt.Sprintf("_%v, _%vErr := attributevalue.MarshalMap(ProcessInputMapRemoveUnderscoreIfNumberKey(%v))\n", column.FieldName, column.FieldName, allColumns[key].JsonName)
				optionalFields += fmt.Sprintf("if _%vErr == nil{\n", column.FieldName)
				optionalFields += fmt.Sprintf("pii.Item[\"%v\"] = &types.AttributeValueMemberM{Value: _%v}\n", column.FieldName, allColumns[key].JsonName)
				optionalFields += "}\n"
			} else {
				insertFields += fmt.Sprintf("\"%v\":     &types.AttributeValueMember%v{Value: %v},\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
			}
		} else {
			if column.FieldType == "L" {
				optionalFields += fmt.Sprintf("if %v != nil {pii.Item[\"%v\"] = &types.AttributeValueMemberL{Value: %vList}}\n", allColumns[key].JsonName, column.FieldName, allColumns[key].JsonName)
			} else if column.FieldType == "N" {
				optionalFields += fmt.Sprintf("if %v != nil {pii.Item[\"%v\"] = &types.AttributeValueMemberN{Value: strconv.Itoa(*%v)}}\n", allColumns[key].JsonName, column.FieldName, allColumns[key].JsonName)
			} else if column.FieldType == "M" {
				optionalFields += fmt.Sprintf("if %v != nil {", allColumns[key].JsonName)
				optionalFields += fmt.Sprintf("_%v, _%vErr := attributevalue.MarshalMap(ProcessInputMapRemoveUnderscoreIfNumberKey(*%v))\n", column.FieldName, column.FieldName, allColumns[key].JsonName)
				optionalFields += fmt.Sprintf("if _%vErr == nil{\n", column.FieldName)
				optionalFields += fmt.Sprintf("pii.Item[\"%v\"] = &types.AttributeValueMemberM{Value: _%v}\n", column.FieldName, allColumns[key].JsonName)
				optionalFields += "}\n"
				optionalFields += "}\n"
			} else {
				optionalFields += fmt.Sprintf("if %v != nil {pii.Item[\"%v\"] = &types.AttributeValueMember%v{Value: *%v}}\n", allColumns[key].JsonName, column.FieldName, column.FieldType, allColumns[key].JsonName)
			}
		}
	}

	query = `
				@@preQuery@@
				@@timestampInits@@
				@@hashInits@@
				@@uuidInits@@
				@@listFields@@
				@@defaultValuesInits@@

				pii := &dynamodb.PutItemInput{
					TableName: aws.String(utils.GetProcessedTableName("@@tableName@@")),
					Item: map[string]types.AttributeValue{
						@@insertFields@@
					},
				}
				@@optionalFields@@
				_, err = db.PutItem(awsContext, pii)

				if err != nil {
					span.RecordError(err)
					span.SetStatus(codes.Error, err.Error())
					QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
					return nil, err
				}
		`
	query = strings.ReplaceAll(query, "@@preQuery@@", preQuery)
	query = strings.ReplaceAll(query, "@@tableName@@", dynamoDBQuery.Table)
	query = strings.ReplaceAll(query, "@@outputClass@@", outputClass)
	query = strings.ReplaceAll(query, "@@returnClass@@", returnClass)
	query = strings.ReplaceAll(query, "@@insertFields@@", insertFields)
	query = strings.ReplaceAll(query, "@@optionalFields@@", optionalFields)
	query = strings.ReplaceAll(query, "@@timestampInits@@", timestampInits)
	query = strings.ReplaceAll(query, "@@hashInits@@", hashInits)
	query = strings.ReplaceAll(query, "@@listFields@@", listFields)
	query = strings.ReplaceAll(query, "@@uuidInits@@", uuidInits)
	query = strings.ReplaceAll(query, "@@defaultValuesInits@@", defaultValuesInits)
	query = strings.ReplaceAll(query, "@@GoFieldName@@", field.GoFieldName)
	return query
}

func generateUpdate(
	field *codegen.Field,
	dynamoDBQuery generated.Directive_DynamodbQuery,
	hashKey generated.Directive_DynamodbColumn,
	rangeKey generated.Directive_DynamodbColumn,
	columns map[string]generated.Directive_DynamodbColumn,
	allColumns map[string]generated.Directive_DynamodbColumn,
	hashes map[string]generated.Directive_Hash,
	timestamps map[string]generated.Directive_Timestamp,
	uuids map[string]bool,
	argumentsRequired map[string]bool,
	mutationConditions map[string]string,
	arrayInputUniqueConditions map[string]generated.Directive_ArrayInputUnique,
) string {
	returnClass := field.TypeReference.Definition.Name
	query := ""
	preQuery := ""

	hashKeyAttributeValue := ""
	if hashKey.FieldName != "" {
		hashKeyAttributeValue = fmt.Sprintf("\"%v\":     &types.AttributeValueMember%v{Value: %v},", hashKey.FieldName, hashKey.FieldType, hashKey.JsonName)
	}
	rangeKeyAttributeValue := ""
	if rangeKey.FieldName != "" {
		rangeKeyAttributeValue = fmt.Sprintf("\"%v\":     &types.AttributeValueMember%v{Value: %v},", rangeKey.FieldName, rangeKey.FieldType, rangeKey.JsonName)
	}

	if len(dynamoDBQuery.PreQueryFunction) > 0 {
		preQuery = fmt.Sprintf("@@fields@@, prqerr := %v.%v(ctx, GetPreloads(ctx), db, @@fields@@)\n", dynamoDBQuery.PreQueryPackage, dynamoDBQuery.PreQueryFunction)
		preQuery += "if prqerr != nil {\n"
		preQuery += "span.RecordError(prqerr)\n"
		preQuery += "span.SetStatus(codes.Error, prqerr.Error())\n"
		preQuery += "QueryFailureCounter.WithLabelValues(\"@@GoFieldName@@\").Inc()\n"
		preQuery += "return nil, prqerr\n"
		preQuery += "}\n"
		args := make([]string, 0)
		// loop over field.Args and extract VarName into args
		for _, arg := range field.Args {
			args = append(args, arg.VarName)
		}
		preQuery = strings.ReplaceAll(preQuery, "@@fields@@", strings.Join(args, ", "))
		preQuery = strings.ReplaceAll(preQuery, "@@GoFieldName@@", field.GoFieldName)
	}

	sortedColumnsKeys := make([]string, 0)
	for k := range columns {
		sortedColumnsKeys = append(sortedColumnsKeys, k)
	}
	sort.Strings(sortedColumnsKeys)
	listFields := ""
	for _, key := range sortedColumnsKeys {
		column := columns[key]
		// TODO we will need to deal with optional lists here
		if column.FieldType == "L" {
			if val, ok := arrayInputUniqueConditions[strings.ToLower(column.JsonName)]; ok {
				listFields += fmt.Sprintf("// loop over %v and ensure there are no duplicate %v values\n", column.JsonName, val.FieldName)
				listFields += fmt.Sprintf("%vMap := make(map[string]bool)\n", val.FieldName)
				if val.ExceptionRegex != "" {
					listFields += fmt.Sprintf("%vException := regexp.MustCompile(`%v`)\n", strings.ToLower(column.JsonName), val.ExceptionRegex)
				}
				listFields += fmt.Sprintf("for i := 0; i < len(%v); i++ {\n", column.JsonName)
				listFields += fmt.Sprintf("if _, ok := %vMap[tags[i].%v]; ok {\n", val.FieldName, ToTitleCase(val.FieldName))
				listFields += fmt.Sprintf("err = errors.New(\"duplicate %v: \" + tags[i].%v)\n", val.FieldName, ToTitleCase(val.FieldName))
				listFields += "span.RecordError(err)\n"
				listFields += "span.SetStatus(codes.Error, err.Error())\n"
				listFields += fmt.Sprintf("QueryFailureCounter.WithLabelValues(\"%s\").Inc()\n", field.GoFieldName)
				listFields += "return nil, err\n}\n"
				if val.ExceptionRegex != "" {
					listFields += fmt.Sprintf("if !%vException.MatchString(tags[i].%v) {\n", strings.ToLower(column.JsonName), ToTitleCase(val.FieldName))
				}
				listFields += fmt.Sprintf("%vMap[tags[i].%v] = true\n", val.FieldName, ToTitleCase(val.FieldName))
				if val.ExceptionRegex != "" {
					listFields += "}\n"
				}
				listFields += "}\n"
			}
			listFields += fmt.Sprintf("%vList, _ := attributevalue.MarshalList(%v)\n", column.JsonName, column.JsonName)
		}
	}

	updateFields := ""

	updateConditionError := "update failed due to constraint mismatch"
	if dynamoDBQuery.UpdateConditionError != "" {
		updateConditionError = dynamoDBQuery.UpdateConditionError
	}

	// add static conditions
	if dynamoDBQuery.UpdateConditionExpression != "" {
		updateFields += fmt.Sprintf("conditionalExpressions = append(conditionalExpressions, \"%v\")\n", dynamoDBQuery.UpdateConditionExpression)

	}
	if len(dynamoDBQuery.UpdateConditionValues) > 0 {
		for _, conditionValue := range dynamoDBQuery.UpdateConditionValues {
			// split on =
			split := strings.Split(conditionValue, "=")
			if len(split) != 3 {
				panic("invalid condition value")
			}
			// add to ueav
			updateFields += fmt.Sprintf("ueav[\"%v\"] = &types.AttributeValueMember%v{Value: \"%v\"}\n", split[0], split[1], split[2])
		}
	}

	for _, key := range sortedColumnsKeys {
		column := columns[key]
		extraCondition := ""
		if val, ok := mutationConditions[strings.ToLower(column.JsonName)]; ok {
			extraCondition = fmt.Sprintf("conditionalExpressions = append(conditionalExpressions, \"%v\")\n", val)
		}
		// do not update hash or range keys
		if column == hashKey {
			if column.FieldType == "N" {
				updateFields += fmt.Sprintf("conditionalExpressions = append(conditionalExpressions, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMember%v{Value: strconv.Itoa(%v)}\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
			} else {
				updateFields += fmt.Sprintf("conditionalExpressions = append(conditionalExpressions, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMember%v{Value: %v}\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
			}
			continue
		}
		if column == rangeKey {
			if column.FieldType == "N" {
				updateFields += fmt.Sprintf("conditionalExpressions = append(conditionalExpressions, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMember%v{Value: strconv.Itoa(%v)}\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
			} else {
				updateFields += fmt.Sprintf("conditionalExpressions = append(conditionalExpressions, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMember%v{Value: %v}\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
			}
			continue
		}
		if argumentsRequired[strings.ToLower(column.JsonName)] {
			if column.FieldType == "L" {
				updateFields += fmt.Sprintf("if %v != nil {updateExpression = append(updateExpression, \"%v = :%v\")\n", allColumns[key].JsonName, column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMemberL{Value: %vList}}\n", column.FieldName, allColumns[key].JsonName)
			} else if column.FieldType == "N" {
				updateFields += fmt.Sprintf("updateExpression = append(updateExpression, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMember%v{Value: strconv.Itoa(%v)}\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
			} else if column.FieldType == "M" {
				updateFields += fmt.Sprintf("_%v, _%vErr := attributevalue.MarshalMap(ProcessInputMapRemoveUnderscoreIfNumberKey(%v))\n", column.FieldName, column.FieldName, allColumns[key].JsonName)
				updateFields += fmt.Sprintf("if _%vErr == nil{\n", column.FieldName)
				updateFields += fmt.Sprintf("updateExpression = append(updateExpression, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMemberM{Value: _%v}\n}\n", column.FieldName, allColumns[key].JsonName)
			} else if column.FieldType == "BOOL" {
				updateFields += fmt.Sprintf("updateExpression = append(updateExpression, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMember%v{Value: %v}\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
			} else {
				updateFields += fmt.Sprintf("if %v == \"\" {\n", allColumns[key].JsonName)
				updateFields += fmt.Sprintf("removeExpression = append(removeExpression, \"%v\")\n", column.FieldName)
				updateFields += "} else {\n"
				updateFields += fmt.Sprintf("updateExpression = append(updateExpression, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMember%v{Value: %v}\n", column.FieldName, column.FieldType, allColumns[key].JsonName)
				updateFields += "}\n"
			}
		} else {
			if column.FieldType == "L" {
				updateFields += fmt.Sprintf("if %v != nil {updateExpression = append(updateExpression, \"%v = :%v\")\n", allColumns[key].JsonName, column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMemberL{Value: %vList}}\n", column.FieldName, allColumns[key].JsonName)
			} else if column.FieldType == "N" {
				updateFields += fmt.Sprintf("if %v != nil {updateExpression = append(updateExpression, \"%v = :%v\")\n", allColumns[key].JsonName, column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMemberN{Value: strconv.Itoa(*%v)}}\n", column.FieldName, allColumns[key].JsonName)
			} else if column.FieldType == "M" {
				updateFields += fmt.Sprintf("if %v != nil {\n_%v, _%vErr := attributevalue.MarshalMap(ProcessInputMapRemoveUnderscoreIfNumberKey(*%v))\n", allColumns[key].JsonName, column.FieldName, column.FieldName, allColumns[key].JsonName)
				updateFields += fmt.Sprintf("if _%vErr == nil{\n", column.FieldName)
				updateFields += fmt.Sprintf("updateExpression = append(updateExpression, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMemberM{Value: _%v}\n}\n}", column.FieldName, allColumns[key].JsonName)
			} else if column.FieldType == "BOOL" {
				updateFields += fmt.Sprintf("if %v != nil {updateExpression = append(updateExpression, \"%v = :%v\")\n", allColumns[key].JsonName, column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMemberBOOL{Value: *%v}}\n", column.FieldName, allColumns[key].JsonName)
			} else {
				updateFields += fmt.Sprintf("if %v != nil {\n", allColumns[key].JsonName)
				updateFields += fmt.Sprintf("if *%v == \"\" {\n", allColumns[key].JsonName)
				updateFields += fmt.Sprintf("removeExpression = append(removeExpression, \"%v\")\n", column.FieldName)
				updateFields += "} else {\n"
				updateFields += fmt.Sprintf("updateExpression = append(updateExpression, \"%v = :%v\")\n", column.FieldName, column.FieldName)
				updateFields += extraCondition
				updateFields += fmt.Sprintf("ueav[\":%v\"] = &types.AttributeValueMemberS{Value: *%v}}\n", column.FieldName, allColumns[key].JsonName)
				updateFields += "}\n"
			}
		}
	}

	query = `
				@@preQuery@@
				@@listFields@@
				expressions := make([]string, 0)
				removeExpression := make([]string, 0)
				updateExpression := make([]string, 0)
				conditionalExpressions := make([]string, 0)
				ueav := make(map[string]types.AttributeValue)
				updateExpression = append(updateExpression, "#UD = :updatedDate")
				ueav[":updatedDate"] = &types.AttributeValueMemberN{Value: strconv.Itoa(int(time.Now().UnixMilli()))}
				@@updateFields@@
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
					TableName: aws.String(utils.GetProcessedTableName("@@tableName@@")),
					Key: map[string]types.AttributeValue{
						@@hashKeyAttributeValue@@
						@@rangeKeyAttributeValue@@
					},
					UpdateExpression: aws.String(strings.Join(expressions, "\n ")),
					ConditionExpression: aws.String(strings.Join(conditionalExpressions, " and ")),
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
						err = errors.New("@@updateConditionError@@")
					}
					span.RecordError(err)
					span.SetStatus(codes.Error, err.Error())
					QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
					return nil, err
				}
		`
	query = strings.ReplaceAll(query, "@@preQuery@@", preQuery)
	query = strings.ReplaceAll(query, "@@tableName@@", dynamoDBQuery.Table)
	query = strings.ReplaceAll(query, "@@updateFields@@", updateFields)
	query = strings.ReplaceAll(query, "@@hashKeyAttributeValue@@", hashKeyAttributeValue)
	query = strings.ReplaceAll(query, "@@rangeKeyAttributeValue@@", rangeKeyAttributeValue)
	query = strings.ReplaceAll(query, "@@returnClass@@", returnClass)
	query = strings.ReplaceAll(query, "@@listFields@@", listFields)
	query = strings.ReplaceAll(query, "@@updateConditionError@@", updateConditionError)
	query = strings.ReplaceAll(query, "@@GoFieldName@@", field.GoFieldName)
	return query
}

func generateDelete(
	field *codegen.Field,
	dynamoDBQuery generated.Directive_DynamodbQuery,
	hashKey generated.Directive_DynamodbColumn,
	rangeKey generated.Directive_DynamodbColumn,
) string {
	returnClass := field.TypeReference.Definition.Name
	query := ""
	initCE := ""
	ce := ""
	initUEAV := ""
	ueav := ""
	preQuery := ""

	hashKeyAttributeValue := ""
	if hashKey.FieldName != "" {
		hashKeyAttributeValue = fmt.Sprintf("\"%v\":     &types.AttributeValueMember%v{Value: %v},", hashKey.FieldName, hashKey.FieldType, hashKey.JsonName)
	}
	rangeKeyAttributeValue := ""
	if rangeKey.FieldName != "" {
		rangeKeyAttributeValue = fmt.Sprintf("\"%v\":     &types.AttributeValueMember%v{Value: %v},", rangeKey.FieldName, rangeKey.FieldType, rangeKey.JsonName)
	}

	if len(dynamoDBQuery.PreQueryFunction) > 0 {
		preQuery = fmt.Sprintf("@@fields@@, prqerr := %v.%v(ctx, GetPreloads(ctx), db, @@fields@@)\n", dynamoDBQuery.PreQueryPackage, dynamoDBQuery.PreQueryFunction)
		preQuery += "if prqerr != nil {\n"
		preQuery += "span.RecordError(prqerr)\n"
		preQuery += "span.SetStatus(codes.Error, prqerr.Error())\n"
		preQuery += "QueryFailureCounter.WithLabelValues(\"@@GoFieldName@@\").Inc()\n"
		preQuery += "return nil, prqerr\n"
		preQuery += "}\n"
		args := make([]string, 0)
		// loop over field.Args and extract VarName into args
		for _, arg := range field.Args {
			args = append(args, arg.VarName)
		}
		preQuery = strings.ReplaceAll(preQuery, "@@fields@@", strings.Join(args, ", "))
		preQuery = strings.ReplaceAll(preQuery, "@@GoFieldName@@", field.GoFieldName)
	}

	deleteConditionError := "delete failed due to constraint mismatch"
	if dynamoDBQuery.DeleteConditionError != "" {
		deleteConditionError = dynamoDBQuery.DeleteConditionError
	}

	if dynamoDBQuery.DeleteConditionExpression != "" {
		initCE = "conditionalExpressions := make([]string, 0)"
		initCE += fmt.Sprintf("\nconditionalExpressions = append(conditionalExpressions, \"%v\")", dynamoDBQuery.DeleteConditionExpression)
		ce = "\nConditionExpression: aws.String(strings.Join(conditionalExpressions, \" and \")),"
	}
	if len(dynamoDBQuery.DeleteConditionValues) > 0 {
		initUEAV = "ueav := make(map[string]types.AttributeValue)"
		// loop over array of condition values
		for _, conditionValue := range dynamoDBQuery.DeleteConditionValues {
			// split on =
			split := strings.Split(conditionValue, "=")
			if len(split) != 3 {
				panic("invalid condition value")
			}
			// add to ueav
			initUEAV += fmt.Sprintf("\nueav[\"%v\"] = &types.AttributeValueMember%v{Value: \"%v\"}", split[0], split[1], split[2])
			ueav = "\nExpressionAttributeValues: ueav,"
		}
	}

	postquery := `if err != nil {
		if strings.Contains(err.Error(), "ConditionalCheckFailedException") {
			err = errors.New("@@deleteConditionError@@")
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
		return &result, err
	}`
	if len(dynamoDBQuery.PostQueryFunction) > 0 {
		postquery = `
		if err == nil {
			return @@customResolverName@@(ctx, GetPreloads(ctx), db,  &result, @@fields@@)
		} else {
			if strings.Contains(err.Error(), "ConditionalCheckFailedException") {
				err = errors.New("@@deleteConditionError@@")
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
			return &result, err
		}
		`
		args := make([]string, 0)
		// loop over field.Args and extract VarName into args
		for _, arg := range field.Args {
			args = append(args, arg.VarName)
		}
		postquery = strings.ReplaceAll(postquery, "@@customResolverName@@", dynamoDBQuery.PostQueryPackage+"."+dynamoDBQuery.PostQueryFunction)
		postquery = strings.ReplaceAll(postquery, "@@fields@@", strings.Join(args, ", "))
	}

	query = `
				@@preQuery@@
				@@initCE@@
				@@initUEAV@@
				_, err = db.DeleteItem(awsContext, &dynamodb.DeleteItemInput{
					TableName: aws.String(utils.GetProcessedTableName("@@tableName@@")),
					Key: map[string]types.AttributeValue{
						@@hashKeyAttributeValue@@
						@@rangeKeyAttributeValue@@
					},@@ce@@ @@ueav@@
				})
				var result model.@@returnClass@@
				@@postQuery@@
		`
	query = strings.ReplaceAll(query, "@@preQuery@@", preQuery)
	query = strings.ReplaceAll(query, "@@tableName@@", dynamoDBQuery.Table)
	query = strings.ReplaceAll(query, "@@hashKeyAttributeValue@@", hashKeyAttributeValue)
	query = strings.ReplaceAll(query, "@@rangeKeyAttributeValue@@", rangeKeyAttributeValue)
	query = strings.ReplaceAll(query, "@@returnClass@@", returnClass)
	query = strings.ReplaceAll(query, "@@postQuery@@", postquery)
	query = strings.ReplaceAll(query, "@@initCE@@", initCE)
	query = strings.ReplaceAll(query, "@@ce@@", ce)
	query = strings.ReplaceAll(query, "@@initUEAV@@", initUEAV)
	query = strings.ReplaceAll(query, "@@ueav@@", ueav)
	query = strings.ReplaceAll(query, "@@deleteConditionError@@", deleteConditionError)
	query = strings.ReplaceAll(query, "@@GoFieldName@@", field.GoFieldName)
	query = strings.Trim(query, "\n")
	return query
}

func generateGetItem(
	field *codegen.Field,
	dynamoDBQuery generated.Directive_DynamodbQuery,
	hashKey generated.Directive_DynamodbColumn,
	rangeKey generated.Directive_DynamodbColumn,
) string {
	outputClass := field.TypeReference.Definition.Fields.ForName("items").Type.Elem.NamedType
	query := ""

	checkExists := make([]string, 0)
	hashKeyAttributeValue := ""
	if hashKey.FieldName != "" {
		hashKeyAttributeValue = fmt.Sprintf("\"%v\":     &types.AttributeValueMember%v{Value: %v},", hashKey.FieldName, hashKey.FieldType, hashKey.JsonName)
		checkExists = append(checkExists, fmt.Sprintf("currentItem.%v == %v", ToTitleCase(hashKey.JsonName), hashKey.JsonName))
	}
	rangeKeyAttributeValue := ""
	if rangeKey.FieldName != "" {
		rangeKeyAttributeValue = fmt.Sprintf("\"%v\":     &types.AttributeValueMember%v{Value: %v},", rangeKey.FieldName, rangeKey.FieldType, rangeKey.JsonName)
		checkExists = append(checkExists, fmt.Sprintf("currentItem.%v == %v", ToTitleCase(rangeKey.JsonName), rangeKey.JsonName))
	}
	query = `
				getItem, getItemErr := db.GetItem(awsContext, &dynamodb.GetItemInput{
					TableName: aws.String(utils.GetProcessedTableName("@@tableName@@")),
					Key: map[string]types.AttributeValue{
						@@hashKeyAttributeValue@@
						@@rangeKeyAttributeValue@@
					},
				})
				var currentItem model.@@outputClass@@
				if getItemErr == nil {
					attributevalue.UnmarshalMap(getItem.Item, &currentItem)
				}
				currentItemExists := false
				if @@checkExists@@ {
					currentItemExists = true
				}
		`
	query = strings.ReplaceAll(query, "@@tableName@@", dynamoDBQuery.Table)
	query = strings.ReplaceAll(query, "@@hashKeyAttributeValue@@", hashKeyAttributeValue)
	query = strings.ReplaceAll(query, "@@rangeKeyAttributeValue@@", rangeKeyAttributeValue)
	query = strings.ReplaceAll(query, "@@outputClass@@", outputClass)
	query = strings.ReplaceAll(query, "@@checkExists@@", strings.Join(checkExists, " && "))
	return query
}

func generateScan(
	field *codegen.Field,
	dynamoDBQuery generated.Directive_DynamodbQuery,
	stringFilters map[string]generated.Directive_DynamodbColumn,
	intFilters map[string]generated.Directive_DynamodbColumn,
	floatFilters map[string]generated.Directive_DynamodbColumn,
	boolFilters map[string]generated.Directive_DynamodbColumn,
	stringKeyFilters map[string]generated.Directive_DynamodbColumn,
	intKeyFilters map[string]generated.Directive_DynamodbColumn,
	floatKeyFilters map[string]generated.Directive_DynamodbColumn,
	boolKeyFilters map[string]generated.Directive_DynamodbColumn,
	outputColumnRequired map[string]bool,
	allColumns map[string]generated.Directive_DynamodbColumn,
	allDynamoDBSubqueries map[string]generated.Directive_DynamodbSubquery,
	allCustomSubqueries map[string]generated.Directive_CustomSubquery,
) string {
	outputClass := field.TypeReference.Definition.Fields.ForName("items").Type.Elem.NamedType
	returnClass := field.TypeReference.Definition.Name
	filterSetup := ""
	for _, column := range stringFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableStringFilterInput", false)
	}
	for _, column := range intFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableIntFilterInput", false)
	}
	for _, column := range floatFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableFloatFilterInput", false)
	}
	for _, column := range boolFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableBooleanFilterInput", false)
	}
	for _, column := range stringKeyFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableStringKeyInput", false)
	}
	for _, column := range intKeyFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableIntKeyInput", false)
	}
	for _, column := range floatKeyFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableFloatKeyInput", false)
	}
	for _, column := range boolKeyFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableBooleanKeyInput", false)
	}
	limitCondition := ""
	if dynamoDBQuery.Limit != 0 {
		limitCondition = fmt.Sprintf("Limit: aws.Int32(%v),", dynamoDBQuery.Limit)
	}
	sortColumn := generateOutputSort(dynamoDBQuery, outputColumnRequired)
	//render the subqueries in alpha order so the diffs are smaller
	sortedSubqueryKeys := make([]string, 0)
	for k := range allDynamoDBSubqueries {
		sortedSubqueryKeys = append(sortedSubqueryKeys, k)
	}
	sort.Strings(sortedSubqueryKeys)
	subqueries := ""
	for _, key := range sortedSubqueryKeys {
		subquery := allDynamoDBSubqueries[key]
		subqueries += generateDynamoSubquery(
			key,
			subquery,
			outputClass,
			allColumns[strings.ToLower(subquery.ForeignHashKey)],
			allColumns[strings.ToLower(subquery.ForeignRangeKey)],
		)
	}
	//render the custom subqueries in alpha order so the diffs are smaller
	sortedSubqueryKeys = make([]string, 0)
	for k := range allCustomSubqueries {
		sortedSubqueryKeys = append(sortedSubqueryKeys, k)
	}
	sort.Strings(sortedSubqueryKeys)
	for _, key := range sortedSubqueryKeys {
		subquery := allCustomSubqueries[key]
		subqueries += generateCustomSubquery(
			key,
			subquery,
			outputClass,
		)
	}
	postquery := `
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
		}
		return &result, err`
	if len(dynamoDBQuery.PostQueryFunction) > 0 {
		postquery = `
		if err == nil {
			return @@customResolverName@@(ctx, GetPreloads(ctx), db, &result)
		} else {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
			return &result, err
		}
		`
		postquery = strings.ReplaceAll(postquery, "@@customResolverName@@", dynamoDBQuery.PostQueryPackage+"."+dynamoDBQuery.PostQueryFunction)
	}
	postquery = strings.ReplaceAll(postquery, "@@GoFieldName@@", field.GoFieldName)
	query := ""
	query = `
				var result model.@@returnClass@@
				items := []model.@@outputClass@@{}
				filterExpression := make([]string, 0)
				eav := make(map[string]types.AttributeValue)
				@@filterSetup@@
				si := &dynamodb.ScanInput{
					TableName:              	 aws.String(utils.GetProcessedTableName("@@tableName@@")),
					FilterExpression:          aws.String(strings.Join(filterExpression, " and ")),
					ExpressionAttributeValues: eav,
					@@limitCondition@@
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
				@@sortColumn@@
				@@subqueries@@
				span.AddEvent("results", trace.WithAttributes(attribute.Int("count", len(result.Items))))
				@@postQuery@@
		`
	query = strings.ReplaceAll(query, "@@tableName@@", dynamoDBQuery.Table)
	query = strings.ReplaceAll(query, "@@limitCondition@@", limitCondition)
	query = strings.ReplaceAll(query, "@@outputClass@@", outputClass)
	query = strings.ReplaceAll(query, "@@sortColumn@@", sortColumn)
	query = strings.ReplaceAll(query, "@@returnClass@@", returnClass)
	query = strings.ReplaceAll(query, "@@filterSetup@@", filterSetup)
	query = strings.ReplaceAll(query, "@@subqueries@@", subqueries)
	query = strings.ReplaceAll(query, "@@postQuery@@", postquery)
	return query
}

func generateQuery(
	field *codegen.Field,
	dynamoDBQuery generated.Directive_DynamodbQuery,
	hashKey generated.Directive_DynamodbColumn,
	rangeKey generated.Directive_DynamodbColumn,
	stringFilters map[string]generated.Directive_DynamodbColumn,
	intFilters map[string]generated.Directive_DynamodbColumn,
	floatFilters map[string]generated.Directive_DynamodbColumn,
	boolFilters map[string]generated.Directive_DynamodbColumn,
	stringKeyFilters map[string]generated.Directive_DynamodbColumn,
	intKeyFilters map[string]generated.Directive_DynamodbColumn,
	floatKeyFilters map[string]generated.Directive_DynamodbColumn,
	boolKeyFilters map[string]generated.Directive_DynamodbColumn,
	argumentsRequired map[string]bool,
	outputColumnRequired map[string]bool,
	allColumns map[string]generated.Directive_DynamodbColumn,
	allDynamoDBSubqueries map[string]generated.Directive_DynamodbSubquery,
	allCustomSubqueries map[string]generated.Directive_CustomSubquery,
) string {
	outputClass := field.TypeReference.Definition.Fields.ForName("items").Type.Elem.NamedType
	returnClass := field.TypeReference.Definition.Name
	query := ""
	hashKeyCondition := ""
	hashKeyAttributeValue := ""
	optionalRangeKeyStart := ""
	optionalRangeKeyEnd := ""
	scanIndexForward := ""
	consistentRead := ""
	if dynamoDBQuery.ScanIndexBackward {
		scanIndexForward = "ScanIndexForward: aws.Bool(false),"
	}
	if dynamoDBQuery.ConsistentRead {
		consistentRead = "ConsistentRead: aws.Bool(true),"
	}
	filterSetup := ""
	rangeKeyProcessed := false
	for _, column := range stringFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableStringFilterInput", column == rangeKey)
		if !rangeKeyProcessed && column == rangeKey {
			rangeKeyProcessed = true
		}
	}
	for _, column := range intFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableIntFilterInput", column == rangeKey)
		if !rangeKeyProcessed && column == rangeKey {
			rangeKeyProcessed = true
		}
	}
	for _, column := range floatFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableFloatFilterInput", column == rangeKey)
		if !rangeKeyProcessed && column == rangeKey {
			rangeKeyProcessed = true
		}
	}
	for _, column := range boolFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableBooleanFilterInput", column == rangeKey)
		if !rangeKeyProcessed && column == rangeKey {
			rangeKeyProcessed = true
		}
	}
	for _, column := range stringKeyFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableStringKeyInput", column == rangeKey)
		if !rangeKeyProcessed && column == rangeKey {
			rangeKeyProcessed = true
		}
	}
	for _, column := range intKeyFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableIntKeyInput", column == rangeKey)
		if !rangeKeyProcessed && column == rangeKey {
			rangeKeyProcessed = true
		}
	}
	for _, column := range floatKeyFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableFloatKeyInput", column == rangeKey)
		if !rangeKeyProcessed && column == rangeKey {
			rangeKeyProcessed = true
		}
	}
	for _, column := range boolKeyFilters {
		filterSetup += generateFilterSetup(column, "ProcessTableBooleanKeyInput", column == rangeKey)
		if !rangeKeyProcessed && column == rangeKey {
			rangeKeyProcessed = true
		}
	}
	if hashKey.FieldName != "" {
		pointer := ""
		if !argumentsRequired[strings.ToLower(hashKey.JsonName)] {
			pointer = "*"
		}
		hashKeyCondition = fmt.Sprintf("kce = append(kce, \"%v=:%v\")", hashKey.FieldName, hashKey.FieldName)
		hashKeyAttributeValue = fmt.Sprintf("eav[\":%v\"] = &types.AttributeValueMember%v{Value: %v%v}", hashKey.FieldName, hashKey.FieldType, pointer, hashKey.JsonName)
	}
	rangeKeyCondition := ""
	rangeKeyAttributeValue := ""
	if rangeKey.FieldName != "" {
		pointer := ""
		if !argumentsRequired[strings.ToLower(rangeKey.JsonName)] {
			pointer = "*"
		}
		if !rangeKeyProcessed {
			rangeKeyCondition = fmt.Sprintf("kce = append(kce, \"%v=:%v\")", rangeKey.FieldName, rangeKey.FieldName)
			rangeKeyAttributeValue = fmt.Sprintf("eav[\":%v\"] = &types.AttributeValueMember%v{Value: %v%v}", rangeKey.FieldName, rangeKey.FieldType, pointer, rangeKey.JsonName)
			if !argumentsRequired[strings.ToLower(rangeKey.JsonName)] {
				optionalRangeKeyStart = fmt.Sprintf("if %v != nil {", rangeKey.JsonName)
				optionalRangeKeyEnd = "}"
			}
		}
	}
	limitCondition := ""
	if dynamoDBQuery.Limit != 0 && dynamoDBQuery.SortColumn == "" {
		limitCondition = fmt.Sprintf("Limit: aws.Int32(%v),", dynamoDBQuery.Limit)
	}

	sortColumn := generateOutputSort(dynamoDBQuery, outputColumnRequired)
	indexCondition := ""
	if dynamoDBQuery.Index != "" {
		indexCondition = fmt.Sprintf("\nIndexName: aws.String(\"%v\"),", dynamoDBQuery.Index)
	}
	//render the subqueries in alpha order so the diffs are smaller
	sortedSubqueryKeys := make([]string, 0)
	for k := range allDynamoDBSubqueries {
		sortedSubqueryKeys = append(sortedSubqueryKeys, k)
	}
	sort.Strings(sortedSubqueryKeys)
	subqueries := ""
	for _, key := range sortedSubqueryKeys {
		subquery := allDynamoDBSubqueries[key]
		subqueries += generateDynamoSubquery(
			key,
			subquery,
			outputClass,
			allColumns[strings.ToLower(subquery.ForeignHashKey)],
			allColumns[strings.ToLower(subquery.ForeignRangeKey)],
		)
	}
	//render the custom subqueries in alpha order so the diffs are smaller
	sortedSubqueryKeys = make([]string, 0)
	for k := range allCustomSubqueries {
		sortedSubqueryKeys = append(sortedSubqueryKeys, k)
	}
	sort.Strings(sortedSubqueryKeys)
	for _, key := range sortedSubqueryKeys {
		subquery := allCustomSubqueries[key]
		subqueries += generateCustomSubquery(
			key,
			subquery,
			outputClass,
		)
	}
	postquery := `
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
	}
	return &result, err`
	if len(dynamoDBQuery.PostQueryFunction) > 0 {
		postquery = `
		if err == nil {
			return @@customResolverName@@(ctx, GetPreloads(ctx), db, &result)
		} else {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			QueryFailureCounter.WithLabelValues("@@GoFieldName@@").Inc()
			return &result, err
		}
		`
		postquery = strings.ReplaceAll(postquery, "@@customResolverName@@", dynamoDBQuery.PostQueryPackage+"."+dynamoDBQuery.PostQueryFunction)
	}
	postquery = strings.ReplaceAll(postquery, "@@GoFieldName@@", field.GoFieldName)
	query = `
				var result model.@@returnClass@@
				items := []model.@@outputClass@@{}
				filterExpression := make([]string, 0)
				eav := make(map[string]types.AttributeValue)
				kce := []string{}
				@@filterSetup@@
				@@hashKeyAttributeValue@@
				@@hashKeyCondition@@
				@@optionalRangeKeyStart@@
				@@rangeKeyAttributeValue@@
				@@rangeKeyCondition@@
				@@optionalRangeKeyEnd@@
				qi := &dynamodb.QueryInput{
					TableName:                 aws.String(utils.GetProcessedTableName("@@tableName@@")),@@indexCondition@@
					KeyConditionExpression:    aws.String(strings.Join(kce, " and ")),
					FilterExpression:          aws.String(strings.Join(filterExpression, " and ")),
					ExpressionAttributeValues: eav,
					@@limitCondition@@@@scanIndexForward@@@@consistentRead@@
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
				@@sortColumn@@
				@@subqueries@@
				span.AddEvent("results", trace.WithAttributes(attribute.Int("count", len(result.Items))))
				@@postQuery@@
		`
	query = strings.ReplaceAll(query, "@@tableName@@", dynamoDBQuery.Table)
	query = strings.ReplaceAll(query, "@@hashKeyCondition@@", hashKeyCondition)
	query = strings.ReplaceAll(query, "@@hashKeyAttributeValue@@", hashKeyAttributeValue)
	query = strings.ReplaceAll(query, "@@rangeKeyCondition@@", rangeKeyCondition)
	query = strings.ReplaceAll(query, "@@rangeKeyAttributeValue@@", rangeKeyAttributeValue)
	query = strings.ReplaceAll(query, "@@limitCondition@@", limitCondition)
	query = strings.ReplaceAll(query, "@@sortColumn@@", sortColumn)
	query = strings.ReplaceAll(query, "@@indexCondition@@", indexCondition)
	query = strings.ReplaceAll(query, "@@outputClass@@", outputClass)
	query = strings.ReplaceAll(query, "@@returnClass@@", returnClass)
	query = strings.ReplaceAll(query, "@@optionalRangeKeyStart@@", optionalRangeKeyStart)
	query = strings.ReplaceAll(query, "@@optionalRangeKeyEnd@@", optionalRangeKeyEnd)
	query = strings.ReplaceAll(query, "@@filterSetup@@", filterSetup)
	query = strings.ReplaceAll(query, "@@scanIndexForward@@", scanIndexForward)
	query = strings.ReplaceAll(query, "@@consistentRead@@", consistentRead)
	query = strings.ReplaceAll(query, "@@subqueries@@", subqueries)
	query = strings.ReplaceAll(query, "@@postQuery@@", postquery)
	return query
}

func generateDynamoSubquery(key string, subquery generated.Directive_DynamodbSubquery, outputClass string, foreignHashKeyColumn generated.Directive_DynamodbColumn, foreignRangeKeyColumn generated.Directive_DynamodbColumn) string {
	if subquery.ForeignRangeKey != "" && foreignRangeKeyColumn.FieldName == "" {
		// there is a compound key but we only have the hash key to query on
		return generateSubqueryWithQuery(
			key,
			subquery,
			outputClass,
			foreignHashKeyColumn,
			foreignRangeKeyColumn,
		)
	} else if subquery.ForeignRangeKey != "" {
		// there is a compound key and we have both keys
		return generateSubqueryWithRange(
			key,
			subquery,
			outputClass,
			foreignHashKeyColumn,
			foreignRangeKeyColumn,
		)
	} else {
		// other conditions list a single hashkey or a list of hash keys
		return generateSubqueryWithGet(
			key,
			subquery,
			outputClass,
			foreignHashKeyColumn,
			foreignRangeKeyColumn,
		)
	}
}

func generateSubqueryWithQuery(key string, subquery generated.Directive_DynamodbSubquery, outputClass string, foreignHashKeyColumn generated.Directive_DynamodbColumn, foreignRangeKeyColumn generated.Directive_DynamodbColumn) string {
	var query string
	query = ""
	if key != "" {
		foreignHashKeyTitle := ToTitleCase(subquery.ForeignHashKey)
		tableName := subquery.Table
		hashKeyFieldType := subquery.HashKeyFieldType
		hashKeyFieldName := subquery.HashKeyFieldName
		hashKeyModelName := subquery.HashKeyModelName
		className := subquery.ClassName
		parentHashKeyModelName := subquery.ParentHashKeyModelName
		lower_parentHashKeyModelName := ToLowerCamelCase(subquery.ParentHashKeyModelName)
		query = `
			// start subquery @@key@@
			// loop through result.Items and their IDs
			if _, ok := GetPreloads(ctx)["Items.@@key@@"]; ok {
				if len(result.Items) > 0 {
					@@foreignHashKeyTitle@@Map := make(map[string][]string)
					@@outputClass@@Map := make(map[string]*model.@@outputClass@@)
		`
		limitCondition := ""
		if subquery.Limit != 0 {
			limitCondition = fmt.Sprintf("Limit: aws.Int32(%v),", subquery.Limit)
		}
		query = query + `for i := 0; i < len(result.Items); i++ {
				@@outputClass@@Map[result.Items[i].@@parentHashKeyModelName@@] = result.Items[i]
				_, ok := @@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@]
				if !ok {
					@@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@] = make([]string, 0)
					@@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@] = append(@@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@], result.Items[i].@@parentHashKeyModelName@@)
					qieav := make(map[string]types.AttributeValue)
					qikce := []string{}
		`
		query = query + fmt.Sprintf(`qieav[":@@hashKeyFieldName@@"] = &types.AttributeValueMember%v{Value: result.Items[i].@@foreignHashKeyTitle@@}`, foreignHashKeyColumn.FieldType)
		query = query + `
							qikce = append(qikce, "@@hashKeyFieldName@@=:@@hashKeyFieldName@@")
							qi := &dynamodb.QueryInput{
								TableName:                 aws.String(utils.GetProcessedTableName("@@tableName@@")),
								KeyConditionExpression:    aws.String(strings.Join(qikce, " and ")),
								ExpressionAttributeValues: qieav,
								ConsistentRead:            aws.Bool(true),
								@@limitCondition@@
							}
							p := dynamodb.NewQueryPaginator(db, qi)
							var out *dynamodb.QueryOutput
							var err error
							for p.HasMorePages() {
								@@key@@ := []model.@@className@@{}
								out, err = p.NextPage(awsContext)
								if err == nil {
									if out.Count > 0 {
										err = attributevalue.UnmarshalListOfMaps(out.Items, &@@key@@)
										if err != nil {
											break
										}
										for j := 0; j < len(@@key@@); j++ {
											@@outputClass@@Map[result.Items[i].@@foreignHashKeyTitle@@].@@key@@ = append(@@outputClass@@Map[result.Items[i].@@foreignHashKeyTitle@@].@@key@@, &@@key@@[j])
										}
									} else {
										@@outputClass@@Map[result.Items[i].@@foreignHashKeyTitle@@].@@key@@ = make([]*model.@@className@@, 0)
									}
								} else {
									break
								}
							}
						}
					}
				}
			}
	  `
		query = strings.ReplaceAll(query, "@@outputClass@@", outputClass)
		query = strings.ReplaceAll(query, "@@key@@", key)
		query = strings.ReplaceAll(query, "@@foreignHashKeyTitle@@", foreignHashKeyTitle)
		query = strings.ReplaceAll(query, "@@tableName@@", tableName)
		query = strings.ReplaceAll(query, "@@hashKeyFieldType@@", hashKeyFieldType)
		query = strings.ReplaceAll(query, "@@hashKeyFieldName@@", hashKeyFieldName)
		query = strings.ReplaceAll(query, "@@hashKeyModelName@@", hashKeyModelName)
		query = strings.ReplaceAll(query, "@@className@@", className)
		query = strings.ReplaceAll(query, "@@limitCondition@@", limitCondition)
		query = strings.ReplaceAll(query, "@@parentHashKeyModelName@@", parentHashKeyModelName)
		query = strings.ReplaceAll(query, "@@lower_parentHashKeyModelName@@", lower_parentHashKeyModelName)
	}
	return query
}

func generateSubqueryWithGet(key string, subquery generated.Directive_DynamodbSubquery, outputClass string, foreignHashKeyColumn generated.Directive_DynamodbColumn, foreignRangeKeyColumn generated.Directive_DynamodbColumn) string {
	var query string
	query = ""
	if key != "" {
		foreignHashKeyTitle := ToTitleCase(subquery.ForeignHashKey)
		tableName := subquery.Table
		hashKeyFieldType := subquery.HashKeyFieldType
		hashKeyFieldName := subquery.HashKeyFieldName
		hashKeyModelName := subquery.HashKeyModelName
		className := subquery.ClassName
		parentHashKeyModelName := subquery.ParentHashKeyModelName
		lower_parentHashKeyModelName := ToLowerCamelCase(subquery.ParentHashKeyModelName)
		hashDeref := ""
		// we must dereference the foreign hash key if it is a pointer
		if !subquery.ForeignHashKeyRequired {
			hashDeref = "*"
		}

		query = query + `
			// start subquery @@key@@
			// loop through result.Items and their IDs
			if _, ok := GetPreloads(ctx)["Items.@@key@@"]; ok {
				if len(result.Items) > 0 {
					@@key@@ := []model.@@className@@{}
					@@foreignHashKeyTitle@@Map := make(map[string][]string)
					@@outputClass@@Map := make(map[string]*model.@@outputClass@@)
					@@foreignHashKeyTitle@@keys := make([]map[string]types.AttributeValue, 0)
		`
		if foreignHashKeyColumn.FieldType == "L" {
			query = query + `for i := 0; i < len(result.Items); i++ {
			`
			// we must do a null check on the foreign hash key if it is a pointer
			if !subquery.ForeignHashKeyRequired {
				query = query + `if result.Items[i].@@foreignHashKeyTitle@@ != nil {
				`
			}
			query = query + `// loop over result.Items[i].@@foreignHashKeyTitle@@
						@@outputClass@@Map[result.Items[i].@@parentHashKeyModelName@@] = result.Items[i]
						for j := 0; j < len(result.Items[i].@@foreignHashKeyTitle@@); j++ {
							_, ok := @@foreignHashKeyTitle@@Map[@@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@[j]]
							if !ok {
								@@foreignHashKeyTitle@@Map[@@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@[j]] = make([]string, 0)
								@@foreignHashKeyTitle@@keys = append(@@foreignHashKeyTitle@@keys, map[string]types.AttributeValue{"@@hashKeyFieldName@@": &types.AttributeValueMember@@hashKeyFieldType@@{Value: @@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@[j]}})
							}
							@@foreignHashKeyTitle@@Map[@@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@[j]] = append(@@foreignHashKeyTitle@@Map[@@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@[j]], result.Items[i].@@parentHashKeyModelName@@)
						}`
			// we must do a null check on the foreign hash key if it is a pointer
			if !subquery.ForeignHashKeyRequired {
				query = query + `		}`
			}
			query = query + `}
			`
		} else if foreignHashKeyColumn.FieldType == "S" {
			query = query + `for i := 0; i < len(result.Items); i++ {
			`
			// we must do a null check on the foreign hash key if it is a pointer
			if !subquery.ForeignHashKeyRequired {
				query = query + `if result.Items[i].@@foreignHashKeyTitle@@ != nil {
				`
			}
			query = query + `@@outputClass@@Map[result.Items[i].@@parentHashKeyModelName@@] = result.Items[i]
						_, ok := @@foreignHashKeyTitle@@Map[@@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@]
						if !ok {
							@@foreignHashKeyTitle@@Map[@@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@] = make([]string, 0)
							@@foreignHashKeyTitle@@keys = append(@@foreignHashKeyTitle@@keys, map[string]types.AttributeValue{"@@hashKeyFieldName@@": &types.AttributeValueMember@@hashKeyFieldType@@{Value: @@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@}})
						}
						@@foreignHashKeyTitle@@Map[@@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@] = append(@@foreignHashKeyTitle@@Map[@@hashDeref@@result.Items[i].@@foreignHashKeyTitle@@], result.Items[i].@@parentHashKeyModelName@@)
			`
			// we must do a null check on the foreign hash key if it is a pointer
			if !subquery.ForeignHashKeyRequired {
				query = query + `		}`
			}
			query = query + `}
			`
		}
		query = query + `if len(@@foreignHashKeyTitle@@keys) > 0 {
				@@foreignHashKeyTitle@@BatchGet, @@foreignHashKeyTitle@@Err := db.BatchGetItem(awsContext, &dynamodb.BatchGetItemInput{
					RequestItems: map[string]types.KeysAndAttributes{
						utils.GetProcessedTableName("@@tableName@@"): {
							Keys: @@foreignHashKeyTitle@@keys,
						},
					},
				})
				if @@foreignHashKeyTitle@@Err == nil {
					if len(@@foreignHashKeyTitle@@BatchGet.Responses[utils.GetProcessedTableName("@@tableName@@")]) > 0 {
						err = attributevalue.UnmarshalListOfMaps(@@foreignHashKeyTitle@@BatchGet.Responses[utils.GetProcessedTableName("@@tableName@@")], &@@key@@)
						for i := 0; i < len(@@key@@); i++ {
							for j := 0; j < len(@@foreignHashKeyTitle@@Map[@@key@@[i].@@hashKeyModelName@@]); j++ {
								@@lower_parentHashKeyModelName@@ := @@foreignHashKeyTitle@@Map[@@key@@[i].@@hashKeyModelName@@][j]
								if entry, ok := @@outputClass@@Map[@@lower_parentHashKeyModelName@@]; ok {
			`
		if subquery.Limit != 1 {
			query = query + `if entry.@@key@@ == nil {
												entry.@@key@@ = make([]*model.@@className@@, 0)
											}
											entry.@@key@@ = append(entry.@@key@@, &@@key@@[i])
										}
									}
								}
							}
						} else {
							err = @@foreignHashKeyTitle@@Err
						}
					}
				}
			}
			// end subquery @@key@@
			`
		} else if subquery.Limit == 1 {
			query = query + `entry.@@key@@ = &@@key@@[i]
										}
									}
								}
							}
						} else {
							err = @@foreignHashKeyTitle@@Err
						}
					}
				}
			}
			// end subquery @@key@@
			`
		}
		query = strings.ReplaceAll(query, "@@outputClass@@", outputClass)
		query = strings.ReplaceAll(query, "@@key@@", key)
		query = strings.ReplaceAll(query, "@@foreignHashKeyTitle@@", foreignHashKeyTitle)
		query = strings.ReplaceAll(query, "@@tableName@@", tableName)
		query = strings.ReplaceAll(query, "@@hashKeyFieldType@@", hashKeyFieldType)
		query = strings.ReplaceAll(query, "@@hashKeyFieldName@@", hashKeyFieldName)
		query = strings.ReplaceAll(query, "@@hashKeyModelName@@", hashKeyModelName)
		query = strings.ReplaceAll(query, "@@className@@", className)
		query = strings.ReplaceAll(query, "@@parentHashKeyModelName@@", parentHashKeyModelName)
		query = strings.ReplaceAll(query, "@@lower_parentHashKeyModelName@@", lower_parentHashKeyModelName)
		query = strings.ReplaceAll(query, "@@hashDeref@@", hashDeref)
	}
	return query
}

func generateSubqueryWithRange(key string, subquery generated.Directive_DynamodbSubquery, outputClass string, foreignHashKeyColumn generated.Directive_DynamodbColumn, foreignRangeKeyColumn generated.Directive_DynamodbColumn) string {
	var query string
	query = ""
	if key != "" {
		foreignHashKeyTitle := ToTitleCase(subquery.ForeignHashKey)
		foreignRangeKeyTitle := ToTitleCase(subquery.ForeignRangeKey)
		tableName := subquery.Table
		hashKeyFieldType := subquery.HashKeyFieldType
		hashKeyFieldName := subquery.HashKeyFieldName
		hashKeyModelName := subquery.HashKeyModelName
		rangeKeyFieldType := subquery.RangeKeyFieldType
		rangeKeyFieldName := subquery.RangeKeyFieldName
		rangeKeyModelName := subquery.RangeKeyModelName
		className := subquery.ClassName
		parentHashKeyModelName := subquery.ParentHashKeyModelName
		parentRangeKeyModelName := subquery.ParentRangeKeyModelName
		lower_parentHashKeyModelName := ToLowerCamelCase(subquery.ParentHashKeyModelName)
		if foreignHashKeyColumn.FieldType == "S" {
			query = `
			// start subquery @@key@@
			// loop through result.Items and their IDs
			if _, ok := GetPreloads(ctx)["Items.@@key@@"]; ok {
				if len(result.Items) > 0 {
					@@key@@ := []model.@@className@@{}
					@@foreignHashKeyTitle@@Map := make(map[string][]string)
					@@outputClass@@Map := make(map[string]*model.@@outputClass@@)
					@@foreignHashKeyTitle@@keys := make([]map[string]types.AttributeValue, 0)
			`
			if foreignRangeKeyColumn.FieldType == "L" {
				query = query + `for i := 0; i < len(result.Items); i++ {
						@@outputClass@@Map[result.Items[i].@@parentHashKeyModelName@@] = result.Items[i]
						// loop over result.Items[i].@@foreignRangeKeyTitle@@
						for j := 0; j < len(result.Items[i].@@foreignRangeKeyTitle@@); j++ {
							_, ok := @@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@]
							if !ok {
								@@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@] = make([]string, 0)
								@@foreignHashKeyTitle@@keys = append(@@foreignHashKeyTitle@@keys, map[string]types.AttributeValue{
									"@@hashKeyFieldName@@": &types.AttributeValueMember@@hashKeyFieldType@@{Value: result.Items[i].@@foreignHashKeyTitle@@},
									"@@rangeKeyFieldName@@": &types.AttributeValueMember@@hashKeyFieldType@@{Value: result.Items[i].@@foreignRangeKeyTitle@@[j]},
								})
							}
						}
						@@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@] = append(@@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@], result.Items[i].@@parentHashKeyModelName@@)
					}
				`
			} else if foreignRangeKeyColumn.FieldType == "S" {
				query = query + `for i := 0; i < len(result.Items); i++ {
						if result.Items[i].@@parentRangeKeyModelName@@ != "" {
							@@outputClass@@Map[result.Items[i].@@parentHashKeyModelName@@+result.Items[i].@@parentRangeKeyModelName@@] = result.Items[i]
							_, ok := @@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@+result.Items[i].@@foreignRangeKeyTitle@@]
							if !ok {
								@@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@+result.Items[i].@@foreignRangeKeyTitle@@] = make([]string, 0)
								@@foreignHashKeyTitle@@keys = append(@@foreignHashKeyTitle@@keys, map[string]types.AttributeValue{
									"@@hashKeyFieldName@@": &types.AttributeValueMember@@hashKeyFieldType@@{Value: result.Items[i].@@foreignHashKeyTitle@@},
									"@@rangeKeyFieldName@@": &types.AttributeValueMember@@hashKeyFieldType@@{Value: result.Items[i].@@foreignRangeKeyTitle@@},
								})
							}
							@@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@+result.Items[i].@@foreignRangeKeyTitle@@] = append(@@foreignHashKeyTitle@@Map[result.Items[i].@@foreignHashKeyTitle@@+result.Items[i].@@foreignRangeKeyTitle@@], result.Items[i].@@parentHashKeyModelName@@+result.Items[i].@@parentRangeKeyModelName@@)
						}
					}
				`
			}
			query = query + `if len(@@foreignHashKeyTitle@@keys) > 0 {
				@@foreignHashKeyTitle@@BatchGet, @@foreignHashKeyTitle@@Err := db.BatchGetItem(awsContext, &dynamodb.BatchGetItemInput{
					RequestItems: map[string]types.KeysAndAttributes{
						utils.GetProcessedTableName("@@tableName@@"): {
							Keys: @@foreignHashKeyTitle@@keys,
						},
					},
				})
				if @@foreignHashKeyTitle@@Err == nil {
					if len(@@foreignHashKeyTitle@@BatchGet.Responses[utils.GetProcessedTableName("@@tableName@@")]) > 0 {
						err = attributevalue.UnmarshalListOfMaps(@@foreignHashKeyTitle@@BatchGet.Responses[utils.GetProcessedTableName("@@tableName@@")], &@@key@@)
						for i := 0; i < len(@@key@@); i++ {
							for j := 0; j < len(@@foreignHashKeyTitle@@Map[@@key@@[i].@@hashKeyModelName@@+@@key@@[i].@@rangeKeyModelName@@]); j++ {
								@@lower_parentHashKeyModelName@@ := @@foreignHashKeyTitle@@Map[@@key@@[i].@@hashKeyModelName@@+@@key@@[i].@@rangeKeyModelName@@][j]
								if entry, ok := @@outputClass@@Map[@@lower_parentHashKeyModelName@@]; ok {
			`
			if subquery.Limit != 1 {
				query = query + `if entry.@@key@@ == nil {
													entry.@@key@@ = make([]*model.@@className@@, 0)
												}
												entry.@@key@@ = append(entry.@@key@@, &@@key@@[i])
											}
										}
									}
								}
							} else {
								err = @@foreignHashKeyTitle@@Err
							}
						}
					}
				}
				// end subquery @@key@@
				`
			} else if subquery.Limit == 1 {
				query = query + `entry.@@key@@ = &@@key@@[i]
											}
										}
									}
								}
							} else {
								err = @@foreignHashKeyTitle@@Err
							}
						}
					}
				}
				// end subquery @@key@@
				`
			}
		}
		query = strings.ReplaceAll(query, "@@outputClass@@", outputClass)
		query = strings.ReplaceAll(query, "@@key@@", key)
		query = strings.ReplaceAll(query, "@@foreignHashKeyTitle@@", foreignHashKeyTitle)
		query = strings.ReplaceAll(query, "@@foreignRangeKeyTitle@@", foreignRangeKeyTitle)
		query = strings.ReplaceAll(query, "@@tableName@@", tableName)
		query = strings.ReplaceAll(query, "@@hashKeyFieldType@@", hashKeyFieldType)
		query = strings.ReplaceAll(query, "@@hashKeyFieldName@@", hashKeyFieldName)
		query = strings.ReplaceAll(query, "@@hashKeyModelName@@", hashKeyModelName)
		query = strings.ReplaceAll(query, "@@rangeKeyFieldType@@", rangeKeyFieldType)
		query = strings.ReplaceAll(query, "@@rangeKeyFieldName@@", rangeKeyFieldName)
		query = strings.ReplaceAll(query, "@@rangeKeyModelName@@", rangeKeyModelName)
		query = strings.ReplaceAll(query, "@@className@@", className)
		query = strings.ReplaceAll(query, "@@parentHashKeyModelName@@", parentHashKeyModelName)
		query = strings.ReplaceAll(query, "@@parentRangeKeyModelName@@", parentRangeKeyModelName)
		query = strings.ReplaceAll(query, "@@lower_parentHashKeyModelName@@", lower_parentHashKeyModelName)
	}
	return query
}

func generateCustomSubquery(key string, customSubquery generated.Directive_CustomSubquery, outputClass string) string {
	var query string
	query = ""
	if key != "" {
		query = `
		// start subquery @@key@@
		// loop through result.Items and their IDs
		if _, ok := GetPreloads(ctx)["Items.@@key@@"]; ok {
			if len(result.Items) > 0 {
				@@customSubqueryName@@(ctx, GetPreloads(ctx), &result)
			}
		}
		// end subquery @@key@@
		`
		query = strings.ReplaceAll(query, "@@customSubqueryName@@", customSubquery.Package+"."+customSubquery.Function)
		query = strings.ReplaceAll(query, "@@key@@", key)
	}
	return query
}

func generateOutputSort(dynamoDBQuery generated.Directive_DynamodbQuery, outputColumnRequired map[string]bool) string {
	sortColumn := ""
	sortDirection := ">"
	if dynamoDBQuery.SortAsc {
		sortDirection = "<"
	}
	if dynamoDBQuery.SortColumn != "" {
		sortColumn = `sort.Slice(result.Items, func(i, j int) bool {`
		sortColumn += fmt.Sprintf("\na := result.Items[i].%v", ToTitleCase(dynamoDBQuery.SortColumn))
		sortColumn += fmt.Sprintf("\nb := result.Items[j].%v", ToTitleCase(dynamoDBQuery.SortColumn))
		if !outputColumnRequired[strings.ToLower(dynamoDBQuery.SortColumn)] {
			sortColumn += "\n if a == nil && b == nil { return true }"
			sortColumn += fmt.Sprintf("\n if a != nil && b == nil { return %t }", dynamoDBQuery.SortAsc)
			sortColumn += fmt.Sprintf("\n if a == nil && b != nil { return %t }", !dynamoDBQuery.SortAsc)
			sortColumn += fmt.Sprintf("\nreturn *a %v *b\n", sortDirection)
		} else {
			sortColumn += fmt.Sprintf("\nreturn a %v b\n", sortDirection)
		}
		sortColumn += `})`
		if dynamoDBQuery.Limit != 0 {
			sortColumn += fmt.Sprintf("\nif len(result.Items) > %v {result.Items = result.Items[:%v]}", dynamoDBQuery.Limit, dynamoDBQuery.Limit)
		}
	}
	return sortColumn
}

// generate the code required for filters
// this gets used in a few places so we moved it here
func generateFilterSetup(column generated.Directive_DynamodbColumn, functionName string, isRangeKey bool) string {
	columnName := column.FieldName
	predicateType := "filterExpression"
	if isRangeKey {
		predicateType = "kce"
	}
	setup := `
	if @@columnName@@ != nil {
		_fe, _eva, err := utils.@@functionName@@("@@columnName@@", @@columnName@@)
		@@predicateType@@ = append(@@predicateType@@, _fe...)
		for k, v := range _eva {
			eav[k] = v
		}
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}
	`
	setup = strings.ReplaceAll(setup, "@@columnName@@", columnName)
	setup = strings.ReplaceAll(setup, "@@predicateType@@", predicateType)
	setup = strings.ReplaceAll(setup, "@@functionName@@", functionName)
	return setup
}

type ResolverBuild struct {
	*File
	HasRoot      bool
	PackageName  string
	ResolverType string
}

type File struct {
	// These are separated because the type definition of the resolver object may live in a different file from the
	// resolver method implementations, for example when extending a type in a different graphql schema file
	Objects         []*codegen.Object
	Resolvers       []*Resolver
	imports         []rewrite.Import
	RemainingSource string
}

func (f *File) Imports() string {
	for _, imp := range f.imports {
		if imp.Alias == "" {
			_, _ = templates.CurrentImports.Reserve(imp.ImportPath)
		} else {
			_, _ = templates.CurrentImports.Reserve(imp.ImportPath, imp.Alias)
		}
	}
	return ""
}

type Resolver struct {
	Object         *codegen.Object
	Field          *codegen.Field
	Comment        string
	Implementation string
}

func gqlToResolverName(base string, gqlname, filenameTmpl string) string {
	gqlname = filepath.Base(gqlname)
	ext := filepath.Ext(gqlname)
	if filenameTmpl == "" {
		filenameTmpl = "{name}.resolvers.go"
	}
	filename := strings.ReplaceAll(filenameTmpl, "{name}", strings.TrimSuffix(gqlname, ext))
	return filepath.Join(base, filename)
}
