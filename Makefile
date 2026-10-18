# nginx-backtrace-ng
NGINX_VERSION ?= 1.31.7
NGINX_SRC     ?=
PREFIX        ?= /opt/nginx
IMAGE         ?= nginx-backtrace-ng
DOCKER        ?= docker


.DEFAULT_GOAL := help
.PHONY: help deps install test test-ubuntu test-debian shell-ubuntu shell-debian clean

help: ## Show this help
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z_-]+:.*## /{printf "  %-14s %s\n",$$1,$$2}' $(MAKEFILE_LIST)
	@echo
	@echo "Vars: NGINX_VERSION=$(NGINX_VERSION) PREFIX=$(PREFIX) NGINX_SRC=<nginx source dir>"

deps: ## Install build dependencies (Debian/Ubuntu, needs sudo)
	sudo apt-get install -y build-essential libunwind-dev libpcre2-dev zlib1g-dev

install: ## Build nginx with this module from NGINX_SRC and install in PREFIX
	@test -n "$(NGINX_SRC)" || { echo "Set NGINX_SRC=/path/to/nginx-source"; exit 1; }
	cd $(NGINX_SRC) && ./configure --prefix=$(PREFIX) --add-module=$(CURDIR) \
		&& $(MAKE) && $(MAKE) install

test: test-ubuntu test-debian ## Run the suite in Docker on Ubuntu and Debian

test-ubuntu: ## Run the suite on Ubuntu 24.04
	$(call run_distro,ubuntu,ubuntu:24.04)

test-debian: ## Run the suite on Debian 12
	$(call run_distro,debian,debian:12)

shell-ubuntu: ## Open a shell in the Ubuntu test image
	$(DOCKER) run --rm -it $(IMAGE):ubuntu bash

shell-debian: ## Open a shell in the Debian test image
	$(DOCKER) run --rm -it $(IMAGE):debian bash

clean: ## Remove the Docker test images
	-$(DOCKER) rmi $(IMAGE):ubuntu $(IMAGE):debian

define run_distro
	$(DOCKER) build --build-arg BASE=$(2) --build-arg NGINX_VERSION=$(NGINX_VERSION) \
		-f tests/Dockerfile -t $(IMAGE):$(1) .
	$(DOCKER) run --rm --init $(IMAGE):$(1)
endef
