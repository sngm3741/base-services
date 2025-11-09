FROM golang:1.23-alpine AS build
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /bin/messenger-ingress .

FROM alpine:3.19
WORKDIR /app

RUN apk add --no-cache tzdata ca-certificates
ENV TZ=Asia/Tokyo

COPY --from=build /bin/messenger-ingress /usr/local/bin/messenger-ingress

EXPOSE 8080
ENTRYPOINT ["messenger-ingress"]
