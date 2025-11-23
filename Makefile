COMPOSE ?= docker compose

ENV_DIR := env
ENVIRONMENT ?= production

# use absolute paths and fix project directory
PROJECT_DIR := $(CURDIR)
SHARED_ENV := $(PROJECT_DIR)/$(ENV_DIR)/shared.env
env_file = $(PROJECT_DIR)/$(ENV_DIR)/$(1).env

compose = ENVIRONMENT=$(1) ENVIRONMENT_FILE=$(call env_file,$(1)) $(COMPOSE) \
          --project-directory $(PROJECT_DIR) \
          --env-file $(SHARED_ENV) --env-file $(call env_file,$(1))
compose_abs = $(call compose,$(1))

ROOT_STACK := docker-compose.yml
REVERSE_PROXY_STACK := reverse-proxy/docker-compose.yml
NETWORKS := infra-edge-network infra-backend-network
DEV_SERVICES := nats messenger-ingress messenger-line-webhook messenger-line-worker messenger-discord-incoming-worker auth-line auth-twitter upload-service

.PHONY: prod-up prod-down prod-restart prod-logs

prod-up: dev-network
	$(call compose_abs,$(ENVIRONMENT)) -f $(ROOT_STACK) -f $(REVERSE_PROXY_STACK) up --build -d

prod-down:
	$(call compose_abs,$(ENVIRONMENT)) -f $(ROOT_STACK) -f $(REVERSE_PROXY_STACK) down

prod-restart: prod-down prod-up

prod-logs:
	$(call compose_abs,$(ENVIRONMENT)) -f $(ROOT_STACK) -f $(REVERSE_PROXY_STACK) logs -f

.PHONY: deploy up up-local down restart logs ps reverse-proxy-up reverse-proxy-down reverse-proxy-logs nginx-up nginx-down nginx-logs \
	fmt test dev-network dev dev-down dev-logs reverse-proxy-dev reverse-proxy-dev-down

deploy: nginx-up up

up:
	$(call compose,$(ENVIRONMENT)) -f $(ROOT_STACK) pull messenger-ingress messenger-line-webhook messenger-line-worker auth-line auth-twitter
	$(call compose,$(ENVIRONMENT)) -f $(ROOT_STACK) up --remove-orphans -d nats messenger-ingress messenger-line-webhook messenger-line-worker auth-line auth-twitter

up-local:
	$(call compose,local) -f $(ROOT_STACK) -f docker-compose.local.yml up --build --remove-orphans nats messenger-ingress messenger-line-webhook messenger-line-worker auth-line auth-twitter

down:
	$(call compose,$(ENVIRONMENT)) -f $(ROOT_STACK) down

restart: down up

logs:
	$(call compose,$(ENVIRONMENT)) -f $(ROOT_STACK) logs -f

ps:
	$(call compose,$(ENVIRONMENT)) -f $(ROOT_STACK) ps

reverse-proxy-up:
	$(call compose,$(ENVIRONMENT)) -f $(REVERSE_PROXY_STACK) up --build -d

reverse-proxy-down:
	$(call compose,$(ENVIRONMENT)) -f $(REVERSE_PROXY_STACK) down

reverse-proxy-logs:
	$(call compose,$(ENVIRONMENT)) -f $(REVERSE_PROXY_STACK) logs -f

reverse-proxy-dev: dev-network
	$(call compose,local) -f $(REVERSE_PROXY_STACK) up --build -d nginx-proxy

reverse-proxy-dev-down:
	$(call compose,$(ENVIRONMENT)) -f $(REVERSE_PROXY_STACK) stop nginx-proxy || true
	$(call compose,$(ENVIRONMENT)) -f $(REVERSE_PROXY_STACK) rm -f nginx-proxy || true

nginx-up: reverse-proxy-up

nginx-down: reverse-proxy-down

nginx-logs: reverse-proxy-logs

fmt:
	cd messenger-service/messenger-ingress && gofmt -w ./cmd ./internal

test:
	cd messenger-service/messenger-ingress && go test ./...

dev-network:
	@for net in $(NETWORKS); do \
		if ! docker network inspect $$net >/dev/null 2>&1; then \
			echo "Creating docker network $$net"; \
			docker network create --driver bridge $$net >/dev/null; \
		fi; \
	done

dev: dev-network
	$(call compose,local) -f $(ROOT_STACK) -f docker-compose.local.yml up --build -d $(DEV_SERVICES)

dev-logs:
	$(call compose,local) -f $(ROOT_STACK) -f docker-compose.local.yml logs -f $(DEV_SERVICES)

dev-down:
	$(call compose,local) -f $(ROOT_STACK) -f docker-compose.local.yml down
