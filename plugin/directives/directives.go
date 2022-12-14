package directives

import (
	_ "embed"
	"path/filepath"
	"syscall"

	"github.com/craftyc0der/gqlgen-dynamodb/internal/code"

	"github.com/99designs/gqlgen/codegen"
	"github.com/99designs/gqlgen/codegen/config"
	"github.com/99designs/gqlgen/codegen/templates"
	"github.com/99designs/gqlgen/plugin"
)

//go:embed directives.gotpl
var directivesTemplate string

func New(filename string, typename string) plugin.Plugin {
	return &Plugin{filename: filename, typeName: typename}
}

type Plugin struct {
	filename string
	typeName string
}

var _ plugin.CodeGenerator = &Plugin{}
var _ plugin.ConfigMutator = &Plugin{}

func (m *Plugin) Name() string {
	return "directives"
}

func (m *Plugin) MutateConfig(cfg *config.Config) error {
	_ = syscall.Unlink(m.filename)
	return nil
}

func (m *Plugin) GenerateCode(data *codegen.Data) error {
	abs, err := filepath.Abs(m.filename)
	if err != nil {
		return err
	}
	pkgName := code.NameForDir(filepath.Dir(abs))

	return templates.Render(templates.Options{
		PackageName: pkgName,
		Filename:    m.filename,
		Data: &DirectiveBuild{
			Data:     data,
			TypeName: m.typeName,
		},
		GeneratedHeader: true,
		Packages:        data.Config.Packages,
		Template:        directivesTemplate,
	})
}

type DirectiveBuild struct {
	*codegen.Data

	TypeName string
}
