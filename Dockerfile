FROM golang:1.18 as builder
WORKDIR /go/src/github.com/craftyc0der/gqlgen-dynamodb

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY graph graph
COPY internal internal
COPY middleware middleware
COPY plugin plugin
COPY routes routes
COPY .gqlconfig .gqlconfig
COPY gqlgen.yml gqlgen.yml
COPY Makefile Makefile
COPY server.go server.go

COPY .git .git

RUN make build

FROM alpine:3.16

RUN addgroup -S database \
    && adduser -S -g database database \
    && apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /go/src/github.com/craftyc0der/gqlgen-dynamodb/bin/gqlgen-dynamodb /app/

RUN chown -R database:database ./

USER database
ENV GIN_MODE=release
ENV PORT=8080

EXPOSE 8080
ENTRYPOINT ["./gqlgen-dynamodb"]