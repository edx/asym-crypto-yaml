.DEFAULT_GOAL := help
.PHONY: help requirements upgrade test shell

# Generates a help message. Borrowed from https://github.com/pydanny/cookiecutter-djangopackage
help: ## Display this help message
	@echo "Please use \`make <target>' where <target> is one of"
	@perl -nle'print $& if m{^[\.a-zA-Z_-]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-25s\033[0m %s\n", $$1, $$2}'

requirements:
	pip install -qr requirements/pip-tools.txt
	pip-sync requirements/development.txt

upgrade: export CUSTOM_COMPILE_COMMAND=make upgrade
upgrade: ## update the pip requirements files to use the latest releases satisfying our constraints
	pip install -q -r requirements/pip-tools.txt
	pip-compile --allow-unsafe --rebuild -o requirements/pip.txt requirements/pip.in
	pip-compile --upgrade -o requirements/pip-tools.txt requirements/pip-tools.in
	pip install -qr requirements/pip.txt
	pip install -qr requirements/pip-tools.txt
	pip-compile --upgrade -o requirements/base.txt requirements/base.in
	pip-compile --upgrade -o requirements/development.txt requirements/development.in

test: ## Run tests using tox
	tox

shell: ## Open a shell in the docker container
	docker run -it --rm -v `pwd`:/app edxops/asym-crypto-yaml /bin/bash

github_docker_build:
	docker build . -t edxops/asym-crypto-yaml:latest

github_docker_tag: github_docker_build
	docker tag edxops/asym-crypto-yaml:latest edxops/asym-crypto-yaml:${GITHUB_SHA}

github_docker_auth:
	echo "$$DOCKERHUB_PASSWORD" | docker login -u "$$DOCKERHUB_USERNAME" --password-stdin

github_docker_push: github_docker_tag github_docker_auth ## push to docker hub
	docker push edxops/asym-crypto-yaml:${GITHUB_SHA}
	docker push edxops/asym-crypto-yaml:latest
