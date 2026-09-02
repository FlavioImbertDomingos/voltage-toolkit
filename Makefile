.PHONY: help up down logs scenario test test-collection lint build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

up: ## Start the demo stack
	docker compose up -d --build

down: ## Stop everything
	docker compose down -v

logs: ## Follow exporter logs
	docker compose logs -f voltage-exporter

scenario: ## Switch the mock scenario, e.g. `make scenario S=slow`
	@test -n "$(S)" || (echo "usage: make scenario S=<healthy|slow|errors|auth-fail|policy-down|keyserver-down|policy-changed>"; exit 1)
	curl -s -X POST http://localhost:8800/mock/scenario/$(S) && echo

test: ## Exporter unit tests (against an in-process mock)
	cd exporter && python -m pytest -q

test-collection: ## Ansible collection unit tests
	python -m pytest -q ansible_collections/flavioimbertdomingos/voltage/tests/unit -p no:cacheprovider

lint: ## ruff
	ruff check exporter mock-voltage grafana
	ruff format --check exporter mock-voltage grafana

build: ## Build images
	docker compose build

clean: down ## Remove outputs
	rm -rf out reports
