FROM golang:1.23-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/auth-twitter ./...

FROM gcr.io/distroless/base-debian12:nonroot

ENV AUTH_TWITTER_HTTP_ADDR=:8080
EXPOSE 8080

COPY --from=build /bin/auth-twitter /bin/auth-twitter

ENTRYPOINT ["/bin/auth-twitter"]
