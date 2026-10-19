# One-command workflow. Run "make help" to list the targets.
#
#   make demo    set everything up (first time) and run the demonstrations
#   make test    set everything up (first time) and run the automated tests
#
# No password is stored anywhere: root logs in through the container's Unix
# socket, automated runs give the demo accounts random in-memory passwords, and
# "make set-password" lets you choose one to log in by hand.

-include .env
export

PYTHON    := .venv/bin/python
COMPOSE   := docker compose
CONTAINER := $(or $(MARIADB_CONTAINER),university-db)
# USER=... only counts when given on the command line (otherwise $(USER) is your login name).
USER_NAME := $(if $(filter command line,$(origin USER)),$(USER),)

.DEFAULT_GOAL := help
.PHONY: help certs up venv setup demo roles examples experiments test unit set-password shell sql lockout down reset clean lint attack parsec benchmark mitm

help:
	@echo "make demo                   start MariaDB 13.1 (first run: also certificates and venv) and run every demonstration"
	@echo "make test                   same setup, then run the pytest suite against the real server"
	@echo "make unit                   server-free unit tests only (no Docker needed)"
	@echo "make roles                  role demo only: the same six actions as each of the four roles"
	@echo "make examples               the standalone SQL tutorial (examples/*.sql)"
	@echo "make experiments            the advanced security experiments (experiments/*.sql)"
	@echo "make attack                 our pair's attacks: PARSEC role demo, the stolen-hash work factor, the MITM"
	@echo "make parsec                 PARSEC role demo only: the full role/DENY matrix under PARSEC over verified TLS"
	@echo "make benchmark              offline work-factor of the three stored formats (guesses/s, mean +/- sd)"
	@echo "make mitm                   man-in-the-middle against TLS: succeeds unverified, blocked when verified"
	@echo "make set-password USER=...  choose a password for a demo account (asked for, never stored)"
	@echo "make sql USER=...           open the mariadb client as that demo account (asks for its password)"
	@echo "make shell                  open the mariadb client as root (unix_socket, no password)"
	@echo "make lockout                experiment 14: PUBLIC hard lockout + recovery on a DISPOSABLE server"
	@echo "make down                   stop the server (keeps the data)"
	@echo "make reset                  stop the server and DELETE its data; next 'make up' starts from scratch"
	@echo "make clean                  reset + delete certificates and the virtual environment"
	@echo "make lint                   ruff (Python) + shellcheck (shell scripts; uses its Docker image if not installed)"

certs:
	@if [ ! -f certs/client-key.pem ]; then bash scripts/generate_certs.sh; fi
	@chmod 600 certs/*-key.pem   # also repairs keys created by older versions of this project

up: certs
	$(COMPOSE) up -d --wait

# The first Python 3.10+ found on PATH (or in Homebrew's directory). macOS ships 3.9 as
# "python3", which is too old; override with  make demo BOOT_PYTHON=/path/to/python3.12
BOOT_PYTHON ?= $(firstword $(foreach p,python3.14 python3.13 python3.12 python3.11 python3.10 python3 /opt/homebrew/bin/python3,$(shell command -v $(p) 2>/dev/null | xargs -I{} sh -c '{} -c "import sys; sys.exit(sys.version_info < (3, 10))" 2>/dev/null && echo {}')))

.venv/.installed: requirements.txt requirements-dev.txt
	@if [ -z "$(BOOT_PYTHON)" ]; then echo "Python 3.10 or newer is required (macOS: brew install python)"; exit 2; fi
	$(BOOT_PYTHON) -m venv .venv
	$(PYTHON) -m pip install --quiet --upgrade pip
	$(PYTHON) -m pip install --quiet -r requirements-dev.txt
	touch $@

venv: .venv/.installed

setup: up venv

roles: setup
	$(PYTHON) app/demo.py

examples: setup
	$(PYTHON) app/sqlrunner.py examples/

experiments: setup
	$(PYTHON) app/sqlrunner.py experiments/

demo: roles examples experiments
	@echo
	@echo "Demo finished: every step above ended in PASS. Run 'make test' for the pytest suite."

# --- our pair's additions: PARSEC as primary, and attacks with measured results ---
parsec: setup
	$(PYTHON) app/parsec_demo.py

benchmark: venv
	$(PYTHON) benchmarks/work_factor.py

mitm: setup
	$(PYTHON) attacks/mitm_demo.py

attack: setup
	@echo "=== PARSEC role demo (the whole model, authenticated with PARSEC) ==="
	$(PYTHON) app/parsec_demo.py
	@echo
	@echo "=== Stolen-hash work factor (guesses/s an attacker gets per format) ==="
	$(PYTHON) benchmarks/work_factor.py
	@echo
	@echo "=== Man-in-the-middle against TLS (succeeds unverified, blocked verified) ==="
	$(PYTHON) attacks/mitm_demo.py

test: setup
	$(PYTHON) -m pytest --cov=app --cov-report=term-missing

unit: venv
	$(PYTHON) -m pytest tests/unit

set-password: setup
	@if [ -z "$(USER_NAME)" ]; then echo "usage: make set-password USER=smith_professor"; exit 2; fi
	$(PYTHON) app/admin.py set-password $(USER_NAME)

shell:
	docker exec -it $(CONTAINER) mariadb

sql:
	@if [ -z "$(USER_NAME)" ]; then echo "usage: make sql USER=smith_professor"; exit 2; fi
	docker exec -it $(CONTAINER) mariadb -u $(USER_NAME) -p university

lockout:
	bash experiments/14_public_lockout.sh

down:
	$(COMPOSE) down

reset:
	$(COMPOSE) down -v

clean: reset
	rm -rf .venv certs .pytest_cache

SHELL_SCRIPTS := scripts/*.sh sql/*.sh experiments/*.sh

lint: venv
	$(PYTHON) -m ruff check app tests benchmarks attacks
	@if command -v shellcheck >/dev/null; then shellcheck $(SHELL_SCRIPTS); \
	else docker run --rm -v "$(CURDIR):/mnt" -w /mnt koalaman/shellcheck:stable $(SHELL_SCRIPTS); fi
	@echo "lint: no findings"
