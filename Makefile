COMPOSE ?= docker compose

ROOT_STACK := docker-compose.yml
REVERSE_PROXY_STACK := reverse-proxy/docker-compose.yml

.PHONY: deploy up up-local down restart logs ps reverse-proxy-up reverse-proxy-down reverse-proxy-logs nginx-up nginx-down nginx-logs fmt test

deploy: nginx-up up

up:
	$(COMPOSE) -f $(ROOT_STACK) pull messenger-gateway messenger-line-webhook messenger-line-worker
	$(COMPOSE) -f $(ROOT_STACK) up --remove-orphans -d nats messenger-gateway messenger-line-webhook messenger-line-worker

up-local:
	$(COMPOSE) -f $(ROOT_STACK) -f docker-compose.local.yml up --build --remove-orphans nats messenger-gateway messenger-line-webhook messenger-line-worker auth-line

down:
	$(COMPOSE) -f $(ROOT_STACK) down

restart: down up

logs:
	$(COMPOSE) -f $(ROOT_STACK) logs -f

ps:
	$(COMPOSE) -f $(ROOT_STACK) ps

reverse-proxy-up:
	$(COMPOSE) -f $(REVERSE_PROXY_STACK) up --build -d

reverse-proxy-down:
	$(COMPOSE) -f $(REVERSE_PROXY_STACK) down

reverse-proxy-logs:
	$(COMPOSE) -f $(REVERSE_PROXY_STACK) logs -f

nginx-up: reverse-proxy-up

nginx-down: reverse-proxy-down

nginx-logs: reverse-proxy-logs

fmt:
	cd messenger-service/messenger-gateway && gofmt -w ./cmd ./internal

test:
	cd messenger-service/messenger-gateway && go test ./...
