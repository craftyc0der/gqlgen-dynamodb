package modelgen

import (
	_ "embed"
	"fmt"
	"go/types"
	"sort"
	"strings"

	"github.com/99designs/gqlgen/codegen/config"
	"github.com/99designs/gqlgen/codegen/templates"
	"github.com/99designs/gqlgen/plugin"
	"github.com/vektah/gqlparser/v2/ast"
)

//go:embed modelgen.gotpl
var modelTemplate string

type BuildMutateHook = func(b *ModelBuild) *ModelBuild

type FieldMutateHook = func(td *ast.Definition, fd *ast.FieldDefinition, f *Field) (*Field, error)

// defaultFieldMutateHook is the default hook for the Plugin which applies the GoTagFieldHook.
func defaultFieldMutateHook(td *ast.Definition, fd *ast.FieldDefinition, f *Field) (*Field, error) {
	return GoTagFieldHook(td, fd, f)
}

func defaultBuildMutateHook(b *ModelBuild) *ModelBuild {
	return b
}

type ModelBuild struct {
	PackageName string
	Interfaces  []*Interface
	Models      []*Object
	Enums       []*Enum
	Scalars     []string
}

type Interface struct {
	Description string
	Name        string
	Implements  []string
}

type Object struct {
	Description string
	// Name is the field's name as it appears in the schema
	Name string
	// GoName is the field's name as it appears in the generated Go code
	GoName      string
	Fields      []*Field
	Implements  []string
	InputObject bool
	List        bool
}

type Field struct {
	Description    string
	Name           string
	GoName         string
	Type           types.Type
	Json           string
	DynamodbColumn string
	Immutable      string
	Hash           string
	Uuid           string
	Timestamp      string
	Tag            string
}

type Enum struct {
	Description string
	Name        string
	Values      []*EnumValue
}

type EnumValue struct {
	Description string
	Name        string
}

func New() plugin.Plugin {
	return &Plugin{
		MutateHook: defaultBuildMutateHook,
		FieldHook:  defaultFieldMutateHook,
	}
}

type Plugin struct {
	MutateHook BuildMutateHook
	FieldHook  FieldMutateHook
}

var _ plugin.ConfigMutator = &Plugin{}

func (m *Plugin) Name() string {
	return "modelgen"
}

func (m *Plugin) MutateConfig(cfg *config.Config) error {
	binder := cfg.NewBinder()

	b := &ModelBuild{
		PackageName: cfg.Model.Package,
	}

	for _, schemaType := range cfg.Schema.Types {
		if cfg.Models.UserDefined(schemaType.Name) {
			continue
		}
		switch schemaType.Kind {
		case ast.Interface, ast.Union:
			it := &Interface{
				Description: schemaType.Description,
				Name:        schemaType.Name,
				Implements:  schemaType.Interfaces,
			}

			b.Interfaces = append(b.Interfaces, it)
		case ast.Object, ast.InputObject:
			if schemaType == cfg.Schema.Query || schemaType == cfg.Schema.Mutation || schemaType == cfg.Schema.Subscription {
				continue
			}
			it := &Object{
				Description: schemaType.Description,
				Name:        schemaType.Name,
			}
			if schemaType.Kind == ast.InputObject {
				it.InputObject = true
			}
			// if it.Name ends with "List"
			// set it.List to true
			if it.Name[len(it.Name)-4:] == "List" {
				it.List = true
			}

			// If Interface A implements interface B, and Interface C also implements interface B
			// then both A and C have methods of B.
			// The reason for checking unique is to prevent the same method B from being generated twice.
			uniqueMap := map[string]bool{}
			for _, implementor := range cfg.Schema.GetImplements(schemaType) {
				if !uniqueMap[implementor.Name] {
					it.Implements = append(it.Implements, implementor.Name)
					uniqueMap[implementor.Name] = true
				}
				// for interface implements
				for _, iface := range implementor.Interfaces {
					if !uniqueMap[iface] {
						it.Implements = append(it.Implements, iface)
						uniqueMap[iface] = true
					}
				}
			}

			for _, field := range schemaType.Fields {
				var typ types.Type
				fieldDef := cfg.Schema.Types[field.Type.Name()]

				if cfg.Models.UserDefined(field.Type.Name()) {
					var err error
					typ, err = binder.FindTypeFromName(cfg.Models[field.Type.Name()].Model[0])
					if err != nil {
						return err
					}
				} else {
					switch fieldDef.Kind {
					case ast.Scalar:
						// no user defined model, referencing a default scalar
						typ = types.NewNamed(
							types.NewTypeName(0, cfg.Model.Pkg(), "string", nil),
							nil,
							nil,
						)

					case ast.Interface, ast.Union:
						// no user defined model, referencing a generated interface type
						typ = types.NewNamed(
							types.NewTypeName(0, cfg.Model.Pkg(), templates.ToGo(field.Type.Name()), nil),
							types.NewInterfaceType([]*types.Func{}, []types.Type{}),
							nil,
						)

					case ast.Enum:
						// no user defined model, must reference a generated enum
						typ = types.NewNamed(
							types.NewTypeName(0, cfg.Model.Pkg(), templates.ToGo(field.Type.Name()), nil),
							nil,
							nil,
						)

					case ast.Object, ast.InputObject:
						// no user defined model, must reference a generated struct
						typ = types.NewNamed(
							types.NewTypeName(0, cfg.Model.Pkg(), templates.ToGo(field.Type.Name()), nil),
							types.NewStruct(nil, nil),
							nil,
						)

					default:
						panic(fmt.Errorf("unknown ast type %s", fieldDef.Kind))
					}
				}

				name := templates.ToGo(field.Name)
				if nameOveride := cfg.Models[schemaType.Name].Fields[field.Name].FieldName; nameOveride != "" {
					name = nameOveride
				}

				typ = binder.CopyModifiersFromAst(field.Type, typ)

				if cfg.StructFieldsAlwaysPointers {
					if isStruct(typ) && (fieldDef.Kind == ast.Object || fieldDef.Kind == ast.InputObject) {
						typ = types.NewPointer(typ)
					}
				}

				// extract all argument directives and decorate the struct with these details
				// we use these decorations later with Golang reflection
				// example
				//
				// type GameserviceSession struct {
				// 	SessionID   string                 `json:"sessionID" dynamodbColumn:"fieldName:sessionId,fieldType:S,jsonName:sessionID" dynamodbav:"sessionId" uuid:"hashKey:true"`
				// 	Title       string                 `json:"title" dynamodbColumn:"fieldName:title,fieldType:S,jsonName:title" dynamodbav:"title"`
				// 	Description string                 `json:"description" dynamodbColumn:"fieldName:description,fieldType:S,jsonName:description" dynamodbav:"description"`
				// 	ScenarioIDs []string               `json:"scenarioIDs" dynamodbColumn:"fieldName:scenarioIds,fieldType:L,jsonName:scenarioIDs" dynamodbav:"scenarioIds"`
				// 	Scenarios   []*GameserviceScenario `json:"scenarios" dynamodbSubquery:"parentHashKeyModelName:SessionID,foreignKey:scenarioIDs,hashKeyModelName:ScenarioID,hashKeyFieldName:scenarioId,hashKeyFieldType:S,className:GameserviceScenario,table:gameservice-scenario,index:,limit:,sortColumn:,sortAsc:"`
				// }

				dynamodbColumn := ""
				fieldRequired := true
				if !field.Type.NonNull {
					fieldRequired = false
				}
				directive := field.Directives.ForName("dynamodbColumn")
				if directive != nil {
					jsonName := field.Name
					arg := directive.Arguments.ForName("fieldName")
					fieldName := field.Name
					if arg != nil {
						fieldName = arg.Value.Raw
					}
					arg = directive.Arguments.ForName("fieldType")
					fieldType := "S"
					if arg != nil {
						fieldType = arg.Value.Raw
					}
					arg = directive.Arguments.ForName("jsonName")
					if arg != nil {
						jsonName = arg.Value.Raw
					}
					omitempty := ""
					if !fieldRequired {
						omitempty = ",omitempty"
					}
					dynamodbColumn = fmt.Sprintf(`dynamodbColumn:"fieldName:%s,fieldType:%s,jsonName:%s" dynamodbav:"%s%s"`, fieldName, fieldType, jsonName, fieldName, omitempty)
				}

				dynamodbSubquery := ""
				directive = field.Directives.ForName("dynamodbSubquery")
				if directive != nil {
					arg := directive.Arguments.ForName("hashKeyModelName")
					hashKeyModelName := arg.Value.Raw

					arg = directive.Arguments.ForName("hashKeyFieldName")
					hashKeyFieldName := arg.Value.Raw

					arg = directive.Arguments.ForName("foreignHashKey")
					foreignHashKey := arg.Value.Raw

					arg = directive.Arguments.ForName("hashKeyFieldType")
					hashKeyFieldType := arg.Value.Raw

					arg = directive.Arguments.ForName("parentHashKeyModelName")
					parentHashKeyModelName := arg.Value.Raw

					arg = directive.Arguments.ForName("foreignHashKeyRequired")
					foreignHashKeyRequired := arg.Value.Raw

					var rangeKeyModelName string
					var rangeKeyFieldName string
					var foreignRangeKey string
					var rangeKeyFieldType string
					var parentRangeKeyModelName string
					var foreignRangeKeyRequired string

					arg = directive.Arguments.ForName("rangeKeyModelName")
					if arg != nil {
						rangeKeyModelName = arg.Value.Raw

						arg = directive.Arguments.ForName("rangeKeyFieldName")
						rangeKeyFieldName = arg.Value.Raw

						arg = directive.Arguments.ForName("rangeKeyFieldType")
						rangeKeyFieldType = arg.Value.Raw

						arg = directive.Arguments.ForName("parentRangeKeyModelName")
						parentRangeKeyModelName = arg.Value.Raw

						arg = directive.Arguments.ForName("foreignRangeKeyRequired")
						foreignRangeKeyRequired = arg.Value.Raw
					}

					arg = directive.Arguments.ForName("foreignRangeKey")
					if arg != nil {
						foreignRangeKey = arg.Value.Raw
					}

					arg = directive.Arguments.ForName("className")
					className := arg.Value.Raw

					arg = directive.Arguments.ForName("table")
					table := arg.Value.Raw

					arg = directive.Arguments.ForName("index")
					index := ""
					if arg != nil {
						index = arg.Value.Raw
					}
					arg = directive.Arguments.ForName("limit")
					limit := ""
					if arg != nil {
						limit = arg.Value.Raw
					}
					arg = directive.Arguments.ForName("sortColumn")
					sortColumn := ""
					if arg != nil {
						sortColumn = arg.Value.Raw
					}
					arg = directive.Arguments.ForName("sortAsc")
					sortAsc := ""
					if arg != nil {
						sortAsc = arg.Value.Raw
					}
					if rangeKeyModelName != "" {
						dynamodbSubquery = fmt.Sprintf(`dynamodbSubquery:"parentHashKeyModelName:%s,foreignHashKeyRequired:%s,foreignHashKey:%s,hashKeyModelName:%s,hashKeyFieldName:%s,hashKeyFieldType:%s,parentRangeKeyModelName:%s,foreignRangeKeyRequired:%s,rangeKeyModelName:%s,rangeKeyFieldName:%s,rangeKeyFieldType:%s,className:%s,table:%s`, parentHashKeyModelName, foreignHashKeyRequired, foreignHashKey, hashKeyModelName, hashKeyFieldName, hashKeyFieldType, parentRangeKeyModelName, foreignRangeKeyRequired, rangeKeyModelName, rangeKeyFieldName, rangeKeyFieldType, className, table)
					} else {
						dynamodbSubquery = fmt.Sprintf(`dynamodbSubquery:"parentHashKeyModelName:%s,foreignHashKeyRequired:%s,foreignHashKey:%s,hashKeyModelName:%s,hashKeyFieldName:%s,hashKeyFieldType:%s,className:%s,table:%s`, parentHashKeyModelName, foreignHashKeyRequired, foreignHashKey, hashKeyModelName, hashKeyFieldName, hashKeyFieldType, className, table)
					}
					if foreignRangeKey != "" {
						dynamodbSubquery = fmt.Sprintf(`%s,foreignRangeKey:%s`, dynamodbSubquery, foreignRangeKey)
					}
					dynamodbSubquery = fmt.Sprintf(`%s,index:%s,limit:%s,sortColumn:%s,sortAsc:%s"`, dynamodbSubquery, index, limit, sortColumn, sortAsc)
				}

				customSubquery := ""
				directive = field.Directives.ForName("customSubquery")
				if directive != nil {
					arg := directive.Arguments.ForName("package")
					sqpackage := ""
					if arg != nil {
						sqpackage = arg.Value.Raw
					}
					arg = directive.Arguments.ForName("function")
					sqfunction := ""
					if arg != nil {
						sqfunction = arg.Value.Raw
					}
					customSubquery = fmt.Sprintf(`customSubquery:"package:%s,function:%s"`, sqpackage, sqfunction)
				}

				immutable := ""
				directive = field.Directives.ForName("immutable")
				if directive != nil {
					arg := directive.Arguments.ForName("errorMessage")
					errorMessage := ""
					if arg != nil {
						errorMessage = arg.Value.Raw
					}
					immutable = fmt.Sprintf(`immutable:"errorMessage:%s"`, errorMessage)
				}

				defaultValue := ""
				directive = field.Directives.ForName("defaultValue")
				if directive != nil {
					arg := directive.Arguments.ForName("envVar")
					envVar := ""
					if arg != nil {
						envVar = arg.Value.Raw
					}
					arg = directive.Arguments.ForName("static")
					static := ""
					if arg != nil {
						static = arg.Value.Raw
					}
					arg = directive.Arguments.ForName("variable")
					variable := ""
					if arg != nil {
						variable = arg.Value.Raw
					}
					defaultValue = fmt.Sprintf(`defaultValue:"envVar:%s,static:%s,variable:%s"`, envVar, static, variable)
				}

				timestamp := ""
				directive = field.Directives.ForName("timestamp")
				if directive != nil {
					arg := directive.Arguments.ForName("immutable")
					tsimmutable := "true"
					if arg != nil {
						tsimmutable = arg.Value.Raw
					}
					timestamp = fmt.Sprintf(`timestamp:"immutable:%s"`, tsimmutable)
				}

				uuid := ""
				directive = field.Directives.ForName("uuid")
				if directive != nil {
					arg := directive.Arguments.ForName("hashKey")
					isHashKey := "false"
					if arg != nil {
						isHashKey = "true"
					}
					uuid = fmt.Sprintf(`uuid:"hashKey:%s"`, isHashKey)
				}

				hash := ""
				directive = field.Directives.ForName("hash")
				if directive != nil {
					arg := directive.Arguments.ForName("fieldName")
					fieldName := field.Name
					if arg != nil {
						fieldName = arg.Value.Raw
					}
					arg = directive.Arguments.ForName("hashType")
					hashType := "SHA256"
					if arg != nil {
						hashType = arg.Value.Raw
					}
					hash = fmt.Sprintf(`hash:"fieldName:%s,hashType:%s"`, fieldName, hashType)
				}

				json := `json:"` + field.Name + `" graphql:"` + field.Name + `"`

				tag := json

				if dynamodbColumn != "" {
					tag += " " + dynamodbColumn
				}
				if dynamodbSubquery != "" {
					tag += " " + dynamodbSubquery
				}
				if customSubquery != "" {
					tag += " " + customSubquery
				}
				if immutable != "" {
					tag += " " + immutable
				}
				if timestamp != "" {
					tag += " " + timestamp
				}
				if hash != "" {
					tag += " " + hash
				}
				if uuid != "" {
					tag += " " + uuid
				}
				if defaultValue != "" {
					tag += " " + defaultValue
				}

				f := &Field{
					Name:           field.Name,
					GoName:         name,
					Type:           typ,
					Description:    field.Description,
					Json:           json,
					DynamodbColumn: dynamodbColumn,
					Immutable:      immutable,
					Timestamp:      timestamp,
					Hash:           hash,
					Uuid:           uuid,
					Tag:            tag,
				}

				if m.FieldHook != nil {
					mf, err := m.FieldHook(schemaType, field, f)
					if err != nil {
						return fmt.Errorf("generror: field %v.%v: %w", it.Name, field.Name, err)
					}
					f = mf
				}

				it.Fields = append(it.Fields, f)
			}

			b.Models = append(b.Models, it)
		case ast.Enum:
			it := &Enum{
				Name:        schemaType.Name,
				Description: schemaType.Description,
			}

			for _, v := range schemaType.EnumValues {
				it.Values = append(it.Values, &EnumValue{
					Name:        v.Name,
					Description: v.Description,
				})
			}

			b.Enums = append(b.Enums, it)
		case ast.Scalar:
			b.Scalars = append(b.Scalars, schemaType.Name)
		}
	}
	sort.Slice(b.Enums, func(i, j int) bool { return b.Enums[i].Name < b.Enums[j].Name })
	sort.Slice(b.Models, func(i, j int) bool { return b.Models[i].Name < b.Models[j].Name })
	sort.Slice(b.Interfaces, func(i, j int) bool { return b.Interfaces[i].Name < b.Interfaces[j].Name })

	// if we are not just turning all struct-type fields in generated structs into pointers, we need to at least
	// check for cyclical relationships and recursive structs
	if !cfg.StructFieldsAlwaysPointers {
		findAndHandleCyclicalRelationships(b)
	}

	for _, it := range b.Enums {
		cfg.Models.Add(it.Name, cfg.Model.ImportPath()+"."+templates.ToGo(it.Name))
	}
	for _, it := range b.Models {
		cfg.Models.Add(it.Name, cfg.Model.ImportPath()+"."+templates.ToGo(it.Name))
	}
	for _, it := range b.Interfaces {
		cfg.Models.Add(it.Name, cfg.Model.ImportPath()+"."+templates.ToGo(it.Name))
	}
	for _, it := range b.Scalars {
		cfg.Models.Add(it, "github.com/99designs/gqlgen/graphql.String")
	}

	if len(b.Models) == 0 && len(b.Enums) == 0 && len(b.Interfaces) == 0 && len(b.Scalars) == 0 {
		return nil
	}

	if m.MutateHook != nil {
		b = m.MutateHook(b)
	}

	err := templates.Render(templates.Options{
		PackageName:     cfg.Model.Package,
		Filename:        cfg.Model.Filename,
		Data:            b,
		GeneratedHeader: true,
		Packages:        cfg.Packages,
		Template:        modelTemplate,
	})
	if err != nil {
		return err
	}

	// We may have generated code in a package we already loaded, so we reload all packages
	// to allow packages to be compared correctly
	cfg.ReloadAllPackages()

	return nil
}

// GoTagFieldHook applies the goTag directive to the generated Field f. When applying the Tag to the field, the field
// name is used when no value argument is present.
func GoTagFieldHook(td *ast.Definition, fd *ast.FieldDefinition, f *Field) (*Field, error) {
	args := make([]string, 0)
	for _, goTag := range fd.Directives.ForNames("goTag") {
		key := ""
		value := fd.Name

		if arg := goTag.Arguments.ForName("key"); arg != nil {
			if k, err := arg.Value.Value(nil); err == nil {
				key = k.(string)
			}
		}

		if arg := goTag.Arguments.ForName("value"); arg != nil {
			if v, err := arg.Value.Value(nil); err == nil {
				value = v.(string)
			}
		}

		args = append(args, key+":\""+value+"\"")
	}

	if len(args) > 0 {
		f.Tag = f.Tag + " " + strings.Join(args, " ")
	}

	return f, nil
}

func isStruct(t types.Type) bool {
	_, is := t.Underlying().(*types.Struct)
	return is
}

// findAndHandleCyclicalRelationships checks for cyclical relationships between generated structs and replaces them
// with pointers. These relationships will produce compilation errors if they are not pointers.
// Also handles recursive structs.
func findAndHandleCyclicalRelationships(b *ModelBuild) {
	for ii, structA := range b.Models {
		for _, fieldA := range structA.Fields {
			if strings.Contains(fieldA.Type.String(), "NotCyclicalA") {
				fmt.Print()
			}
			if !isStruct(fieldA.Type) {
				continue
			}

			// the field Type string will be in the form "github.com/99designs/gqlgen/codegen/testserver/followschema.LoopA"
			// we only want the part after the last dot: "LoopA"
			// this could lead to false positives, as we are only checking the name of the struct type, but these
			// should be extremely rare, if it is even possible at all.
			fieldAStructNameParts := strings.Split(fieldA.Type.String(), ".")
			fieldAStructName := fieldAStructNameParts[len(fieldAStructNameParts)-1]

			// find this struct type amongst the generated structs
			for jj, structB := range b.Models {
				if structB.Name != fieldAStructName {
					continue
				}

				// check if structB contains a cyclical reference back to structA
				var cyclicalReferenceFound bool
				for _, fieldB := range structB.Fields {
					if !isStruct(fieldB.Type) {
						continue
					}

					fieldBStructNameParts := strings.Split(fieldB.Type.String(), ".")
					fieldBStructName := fieldBStructNameParts[len(fieldBStructNameParts)-1]
					if fieldBStructName == structA.Name {
						cyclicalReferenceFound = true
						fieldB.Type = types.NewPointer(fieldB.Type)
						// keep looping in case this struct has additional fields of this type
					}
				}

				// if this is a recursive struct (i.e. structA == structB), ensure that we only change this field to a pointer once
				if cyclicalReferenceFound && ii != jj {
					fieldA.Type = types.NewPointer(fieldA.Type)
					break
				}
			}
		}
	}
}
