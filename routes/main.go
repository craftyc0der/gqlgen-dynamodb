package routes

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/craftyc0der/gqlgen-dynamodb/graph"
	"github.com/gin-gonic/gin"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel/trace"
)

var (
	Router = gin.New()
)

// Define the Graphql handler
func graphqlHandler() gin.HandlerFunc {
	// NewExecutableSchema and Config are in the generated.go file
	// Resolver is in the resolver.go file
	h := graph.GetDefaultHandler()

	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

// Defining the Playground handler
func playgroundHandler() gin.HandlerFunc {
	url := "/query"
	if _url := os.Getenv("URL"); _url != "" {
		url = _url
	}
	h := playground.Handler("GraphQL", url)

	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func Run(opentelemetry bool, serviceName string) *gin.Engine {
	// setup sentry
	Router.Use(gin.Recovery())

	if opentelemetry {
		Router.Use(otelgin.Middleware(serviceName))
		// use custom logger
		Router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
			var statusColor, methodColor, resetColor string
			if param.IsOutputColor() {
				statusColor = param.StatusCodeColor()
				methodColor = param.MethodColor()
				resetColor = param.ResetColor()
			}

			if param.Latency > time.Minute {
				param.Latency = param.Latency.Truncate(time.Second)
			}
			return fmt.Sprintf("[GIN] %v |%s %3d %s| %13v | %15s |%s %-7s %s %#v | traceID=%s\n%s",
				param.TimeStamp.Format("2006/01/02 - 15:04:05"),
				statusColor, param.StatusCode, resetColor,
				param.Latency,
				param.ClientIP,
				methodColor, param.Method, resetColor,
				param.Path,
				getTraceId(param.Request.Context()),
				param.ErrorMessage,
			)
		}))
	} else {
		// use default logger
		Router.Use(gin.Logger())
	}

	// install prometheus
	p := ginprometheus.NewPrometheus("gin")
	p.Use(Router)

	// setup graphql query engine
	query := Router.Group("/query")

	query.POST("", graphqlHandler())

	// setup graphql playground
	Router.GET("/", playgroundHandler())
	return Router
}

func getTraceId(ctx context.Context) string {
	if span := trace.SpanFromContext(ctx); span != nil {
		return span.SpanContext().TraceID().String()
	}
	return ""
}
