.DEFAULT_GOAL := help
.PHONY: help build upgrade upgrade-requirements test run-tests shell

# Generates a help message. Borrowed from https://github.com/pydanny/cookiecutter-djangopackage
help: ## Display this help message
	@echo "Please use \`make <target>' where <target> is one of"
	@perl -nle'print $& if m{^[\.a-zA-Z_-]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-25s\033[0m %s\n", $$1, $$2}'

requirements:
	pip install -qr requirements/development.txt

upgrade: export CUSTOM_COMPILE_COMMAND=make upgrade
upgrade: ## update the pip requirements files to use the latest releases satisfying our constraints
	pip install -q -r requirements/pip-tools.txt
	pip-compile --upgrade -o requirements/pip-tools.txt requirements/pip-tools.in
	pip-compile --upgrade -o requirements/requirements.txt requirements/requirements.in
	pip-compile --upgrade -o requirements/development.txt requirements/development.in

test: ## Run tests using tox
	tox

shell: ## Open a shell in the docker container
	docker run -it --rm -v `pwd`:/app edxops/asym-crypto-yaml /bin/bash
