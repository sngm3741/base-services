FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN apk add --no-cache ca-certificates && \
    GOCACHE=/tmp/go-cache GOMODCACHE=/tmp/go-mod go mod download && \
    GOCACHE=/tmp/go-cache GOMODCACHE=/tmp/go-mod go build -o upload-service

FROM alpine:3
WORKDIR /app
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/upload-service /usr/local/bin/upload-service
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/upload-service"]
