# ## Sets default action to be help
# .DEFAULT_GOAL := help

# ## Build the help output for this makefile
# .PHONY: help
# help: ## Shows Help
# 	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":[^:]*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


# .PHONY: clean
# clean: ## Clean up directories, mainly the venv.
# 	echo "INFO: Cleaning up directories"
# 	rm -rf ./venv


# .PHONY: setup
# setup: ## Setup virtualenv
# 	echo "INFO: Setting up python 3.9 venv."
# 	$(shell which python3.9) -m venv venv
# 	. venv/bin/activate && pip install -U pip && pip install -r src/requirements.txt


# .PHONY: black
# black: ## Run black test.
# 	echo "INFO: Running black"
# 	. venv/bin/activate && black --check src/


# .PHONY: flake8
# flake8: ## Run flake8 test.
# 	echo "INFO: Running flake8"
# 	. venv/bin/activate && flake8 src/


# .PHONY: isort
# isort: ## Run isort test.
# 	echo "INFO: Running isort"
# 	. venv/bin/activate && isort --check --diff src/


# .PHONY: run_no_post_datadog
# run_no_post_datadog: ## Run python code for projects and do not post metrics to Datadog.
# 	echo "INFO: Will not post metrics to Datadog."
# 	. venv/bin/activate && python src/main.py --post_to_datadog "no"


# .PHONY: run_post_datadog
# run_post_datadog: ## Run python code for projects and post metrics to Datadog.
# 	echo "INFO: Posting metrics to Datadog."
# 	. venv/bin/activate && python src/main.py --post_to_datadog "yes"
