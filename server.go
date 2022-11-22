package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/craftyc0der/gqlgen-dynamodb/routes"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc/credentials"
)

const defaultPort = "8080"
const serviceName = "gqlgen-dynamodb"
const insecure = true

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = defaultPort
	}

	collectorURL := os.Getenv("COLLECTOR_URL")
	useOpenTelemetry := false
	if collectorURL != "" {
		cleanup := initTracer(collectorURL)
		defer cleanup(context.Background())
		if cleanup != nil {
			useOpenTelemetry = true
		}
	}

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	// the below function sets up the routes for the server
	// this includes the graphql stuff
	r := routes.Run(useOpenTelemetry, serviceName)
	// this configures the basic server stuff
	s := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}
	s.SetKeepAlivesEnabled(false)
	s.ListenAndServe()
}

func initTracer(collectorURL string) func(context.Context) error {

	secureOption := otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, ""))
	if insecure {
		secureOption = otlptracegrpc.WithInsecure()
	}

	exporter, err := otlptrace.New(
		context.Background(),
		otlptracegrpc.NewClient(
			secureOption,
			otlptracegrpc.WithEndpoint(collectorURL),
		),
	)

	if err != nil {
		log.Fatal(err)
	}
	resources, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
			attribute.String("library.language", "go"),
		),
	)
	if err != nil {
		log.Print("Could not set resources: ", err)
	}
	otel.SetTracerProvider(
		sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(resources),
		),
	)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return exporter.Shutdown
}
