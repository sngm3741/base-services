FROM golang:1.23-alpine AS build
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /bin/messenger-gateway .

FROM alpine:3.19
WORKDIR /app

RUN apk add --no-cache tzdata ca-certificates
ENV TZ=Asia/Tokyo

COPY --from=build /bin/messenger-gateway /usr/local/bin/messenger-gateway

EXPOSE 3000
ENTRYPOINT ["messenger-gateway"]
