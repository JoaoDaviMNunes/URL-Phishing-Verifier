SHELL := /bin/bash
.DEFAULT_GOAL := help

# ============================================================
# Variaveis (podem ser sobrescritas: make train DATASET=...)
# ============================================================
SYSTEM_PYTHON ?= python3
VENV_DIR ?= venv-url
VENV_PYTHON := $(if $(wildcard $(VENV_DIR)/bin/python3),$(VENV_DIR)/bin/python3,$(VENV_DIR)/bin/python)
VENV_PIP := $(VENV_DIR)/bin/pip
VENV_READY_FILE := $(VENV_DIR)/.ready
VENV_DEPS_FILE := $(VENV_DIR)/.deps-installed
PROJECT_ROOT := $(CURDIR)

# Se o venv existir, usa automaticamente; senao cai para python do sistema.
PYTHON ?= $(if $(wildcard $(VENV_PYTHON)),$(VENV_PYTHON),$(SYSTEM_PYTHON))
PIP ?= $(PYTHON) -m pip
PY_RUN = PYTHONPATH="$(PROJECT_ROOT)" $(PYTHON)

# Arquivos e pastas
REQUIREMENTS ?= requirements.txt
ARTIFACTS_DIR ?= artifacts
DATA_DIR ?= data
RAW_DIR ?= $(DATA_DIR)/raw
PROCESSED_DIR ?= $(DATA_DIR)/processed

# Datasets padrao
PHISHTANK_DUMP ?= $(RAW_DIR)/phish_dump.txt
MENDELEY_INPUT ?= $(RAW_DIR)/mendeley_phishing.csv
ALEXA_INPUT ?= $(RAW_DIR)/alexa_top_sites.csv

PHISHTANK_CSV ?= $(RAW_DIR)/phishing_phishtank.csv
MENDELEY_CSV ?= $(RAW_DIR)/phishing_mendeley.csv
ALEXA_CSV ?= $(RAW_DIR)/legit_alexa.csv
DATASET ?= $(PROCESSED_DIR)/dataset.csv

# Colunas e parametros de treino/coleta
URL_COLUMN ?= url
LABEL_COLUMN ?= label
DOMAIN_COLUMN ?= domain
GEO_METHOD ?= dns_api
BETA ?= 2.0
LIMIT ?=

# API / Dashboard
API_HOST ?= 0.0.0.0
API_PORT ?= 8000
MODEL_ARTIFACTS_DIR ?= $(ARTIFACTS_DIR)
STREAMLIT_PORT ?= 8501

# ============================================================
# Help
# ============================================================
.PHONY: help
help: ## Mostra esta ajuda
	@echo ""
	@echo "URL-Phishing-Verifier - Makefile"
	@echo ""
	@echo "Uso:"
	@echo "  make <target> [VAR=valor]"
	@echo ""
	@echo "Exemplos:"
	@echo "  make venv"
	@echo "  make setup"
	@echo "  make all"
	@echo "  make install"
	@echo "  make collect-all PHISHTANK_DUMP=https://exemplo/feed.txt"
	@echo "  make train BETA=3.0 DATASET=data/merged/dataset.csv"
	@echo "  make train-ssl-geo GEO_METHOD=ccTLD"
	@echo "  make api API_PORT=9000"
	@echo "  make dashboard STREAMLIT_PORT=8502"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-28s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort
	@echo ""
	@echo "Variaveis comuns:"
	@echo "  SYSTEM_PYTHON=$(SYSTEM_PYTHON)"
	@echo "  VENV_DIR=$(VENV_DIR)"
	@echo "  PYTHON=$(PYTHON)"
	@echo "  ARTIFACTS_DIR=$(ARTIFACTS_DIR)"
	@echo "  DATASET=$(DATASET)"
	@echo "  GEO_METHOD=$(GEO_METHOD)"
	@echo "  BETA=$(BETA)"
	@echo ""

# ============================================================
# Setup / utilitarios
# ============================================================
.PHONY: venv-recreate venv-remove venv-info activate install-dev upgrade-pip check-python compile lint ensure-dirs env-ready
$(VENV_READY_FILE):
	@$(SYSTEM_PYTHON) -m venv "$(VENV_DIR)"
	@"$(VENV_DIR)/bin/python" -m pip install --upgrade pip
	@touch "$(VENV_READY_FILE)"
	@echo "Venv criado em $(VENV_DIR)"

venv: $(VENV_READY_FILE) ## Cria ambiente virtual em $(VENV_DIR)
	@echo "Venv pronto em $(VENV_DIR)"

$(VENV_DEPS_FILE): $(REQUIREMENTS) $(VENV_READY_FILE)
	$(PIP) install -r $(REQUIREMENTS)
	@touch "$(VENV_DEPS_FILE)"

venv-recreate: ## Recria o ambiente virtual (remove e cria novamente)
	@rm -rf "$(VENV_DIR)"
	@$(MAKE) venv

venv-remove: ## Remove o ambiente virtual
	@rm -rf "$(VENV_DIR)"
	@echo "Venv removido: $(VENV_DIR)"

venv-info: ## Mostra informacoes do ambiente virtual atual
	@echo "VENV_DIR=$(VENV_DIR)"
	@echo "PYTHON em uso: $(PYTHON)"
	@$(PYTHON) --version

install: $(VENV_DEPS_FILE) ## Instala dependencias do projeto no venv
	@echo "Dependencias instaladas em $(VENV_DIR)"

install-dev: install ## Instala dependencias + ferramentas de desenvolvimento no venv
	$(PIP) install -r $(REQUIREMENTS) pytest ruff

upgrade-pip: venv ## Atualiza pip do venv
	$(PIP) install --upgrade pip
	@touch "$(VENV_READY_FILE)"

check-python: ## Exibe versao do Python em uso
	@$(PYTHON) --version
	@echo "PYTHONPATH=$(PROJECT_ROOT)"

compile: ## Valida sintaxe de todos os .py (py_compile)
	@$(PYTHON) -m py_compile $$(ls -1 **/*.py 2>/dev/null | tr '\n' ' ')

lint: ## Roda ruff (se instalado)
	@ruff check . || true

ensure-dirs: ## Cria diretorios de dados/artifacts
	@mkdir -p "$(RAW_DIR)" "$(PROCESSED_DIR)" "$(ARTIFACTS_DIR)"

env-ready: install ## Garante venv + dependencias instaladas
	@echo "Ambiente pronto para execucao."

# ============================================================
# Coleta de dados
# ============================================================
.PHONY: collect-phishtank collect-mendeley collect-alexa collect-all
collect-phishtank: env-ready ensure-dirs ## Coleta URLs maliciosas via dump/feed PhishTank (path ou URL HTTP)
	@echo "Fonte PhishTank: $(PHISHTANK_DUMP)"
	$(PY_RUN) scripts/collect_phishtank.py \
		--dump-url-or-path "$(PHISHTANK_DUMP)" \
		--out "$(PHISHTANK_CSV)" \
		$(if $(LIMIT),--limit $(LIMIT),)

collect-mendeley: env-ready ensure-dirs ## Coleta URLs maliciosas do Mendeley (CSV/TSV local)
	@if [ -f "$(MENDELEY_INPUT)" ]; then \
		$(PY_RUN) scripts/collect_mendeley_phishing.py \
			--input "$(MENDELEY_INPUT)" \
			--out "$(MENDELEY_CSV)" \
			--url-column "$(URL_COLUMN)" \
			$(if $(LIMIT),--limit $(LIMIT),); \
	else \
		echo "[WARN] Arquivo nao encontrado: $(MENDELEY_INPUT)"; \
		echo "[WARN] Gerando CSV vazio em $(MENDELEY_CSV)"; \
		mkdir -p "$(RAW_DIR)"; \
		printf "url,label\n" > "$(MENDELEY_CSV)"; \
	fi

collect-alexa: env-ready ensure-dirs ## Coleta URLs legitimas (Alexa top sites CSV/TXT)
	@if [ -f "$(ALEXA_INPUT)" ]; then \
		$(PY_RUN) scripts/collect_alexa_legit.py \
			--input "$(ALEXA_INPUT)" \
			--out "$(ALEXA_CSV)" \
			--domain-column "$(DOMAIN_COLUMN)" \
			$(if $(LIMIT),--limit $(LIMIT),); \
	else \
		echo "[WARN] Arquivo nao encontrado: $(ALEXA_INPUT)"; \
		echo "[WARN] Gerando CSV vazio em $(ALEXA_CSV)"; \
		mkdir -p "$(RAW_DIR)"; \
		printf "url,label\n" > "$(ALEXA_CSV)"; \
	fi

collect-all: collect-phishtank collect-mendeley collect-alexa ## Executa todas as coletas
	@echo "Coletas concluidas em $(RAW_DIR)"

.PHONY: merge-datasets
merge-datasets: env-ready ensure-dirs ## Junta CSVs brutos em data/processed/dataset.csv
	$(PY_RUN) scripts/merge_datasets.py \
		--inputs "$(PHISHTANK_CSV)" "$(MENDELEY_CSV)" "$(ALEXA_CSV)" \
		--out "$(DATASET)"

# ============================================================
# Treino e artefatos
# ============================================================
.PHONY: train train-ssl train-geo train-ssl-geo train-cctld
train: env-ready ## Treina LightGBM com features basicas (sem SSL/Geo)
	@test -f "$(DATASET)" || { echo "Dataset nao encontrado: $(DATASET)"; echo "Rode: make merge-datasets (ou defina DATASET=...)"; exit 1; }
	$(PY_RUN) scripts/train_model.py \
		--csv "$(DATASET)" \
		--url-column "$(URL_COLUMN)" \
		--label-column "$(LABEL_COLUMN)" \
		--artifacts-dir "$(ARTIFACTS_DIR)" \
		--beta-fbeta "$(BETA)"

train-ssl: env-ready ## Treina com features SSL habilitadas
	@test -f "$(DATASET)" || { echo "Dataset nao encontrado: $(DATASET)"; echo "Rode: make merge-datasets (ou defina DATASET=...)"; exit 1; }
	$(PY_RUN) scripts/train_model.py \
		--csv "$(DATASET)" \
		--url-column "$(URL_COLUMN)" \
		--label-column "$(LABEL_COLUMN)" \
		--artifacts-dir "$(ARTIFACTS_DIR)" \
		--beta-fbeta "$(BETA)" \
		--enable-ssl

train-geo: env-ready ## Treina com geolocalizacao habilitada (GEO_METHOD=dns_api|ccTLD)
	@test -f "$(DATASET)" || { echo "Dataset nao encontrado: $(DATASET)"; echo "Rode: make merge-datasets (ou defina DATASET=...)"; exit 1; }
	$(PY_RUN) scripts/train_model.py \
		--csv "$(DATASET)" \
		--url-column "$(URL_COLUMN)" \
		--label-column "$(LABEL_COLUMN)" \
		--artifacts-dir "$(ARTIFACTS_DIR)" \
		--beta-fbeta "$(BETA)" \
		--enable-geo \
		--geo-method "$(GEO_METHOD)"

train-ssl-geo: env-ready ## Treina com SSL + Geo habilitados
	@test -f "$(DATASET)" || { echo "Dataset nao encontrado: $(DATASET)"; echo "Rode: make merge-datasets (ou defina DATASET=...)"; exit 1; }
	$(PY_RUN) scripts/train_model.py \
		--csv "$(DATASET)" \
		--url-column "$(URL_COLUMN)" \
		--label-column "$(LABEL_COLUMN)" \
		--artifacts-dir "$(ARTIFACTS_DIR)" \
		--beta-fbeta "$(BETA)" \
		--enable-ssl \
		--enable-geo \
		--geo-method "$(GEO_METHOD)"

train-cctld: ## Treina com Geo via ccTLD (mais rapido, sem API externa)
	$(MAKE) train-geo GEO_METHOD=ccTLD

.PHONY: pipeline pipeline-ssl-geo
pipeline: collect-all merge-datasets train ## Pipeline completo padrao (coleta -> merge -> treino)
	@echo "Pipeline completo finalizado."

pipeline-ssl-geo: collect-all merge-datasets train-ssl-geo ## Pipeline completo com SSL+Geo
	@echo "Pipeline SSL+Geo finalizado."

# ============================================================
# Servicos (API / Dashboard)
# ============================================================
.PHONY: api api-dev dashboard dashboard-dev
api: env-ready ## Sobe API FastAPI (sem hot reload)
	@test -f "$(MODEL_ARTIFACTS_DIR)/model.joblib" || { echo "Modelo nao encontrado em $(MODEL_ARTIFACTS_DIR). Rode: make train"; exit 1; }
	@PYTHONPATH="$(PROJECT_ROOT)" MODEL_ARTIFACTS_DIR="$(MODEL_ARTIFACTS_DIR)" API_HOST="$(API_HOST)" API_PORT="$(API_PORT)" \
	$(PYTHON) scripts/run_api.py

api-dev: env-ready ## Sobe API FastAPI com uvicorn --reload
	@test -f "$(MODEL_ARTIFACTS_DIR)/model.joblib" || { echo "Modelo nao encontrado em $(MODEL_ARTIFACTS_DIR). Rode: make train"; exit 1; }
	@PYTHONPATH="$(PROJECT_ROOT)" MODEL_ARTIFACTS_DIR="$(MODEL_ARTIFACTS_DIR)" \
	$(PYTHON) -m uvicorn url_phishing_verifier.api.app:app --host "$(API_HOST)" --port "$(API_PORT)" --reload

dashboard: env-ready ## Sobe Streamlit dashboard
	@test -f "$(MODEL_ARTIFACTS_DIR)/model.joblib" || { echo "Modelo nao encontrado em $(MODEL_ARTIFACTS_DIR). Rode: make train"; exit 1; }
	@PYTHONPATH="$(PROJECT_ROOT)" MODEL_ARTIFACTS_DIR="$(MODEL_ARTIFACTS_DIR)" \
	$(PYTHON) -m streamlit run streamlit_app.py --server.port "$(STREAMLIT_PORT)"

dashboard-dev: dashboard ## Alias para dashboard

# ============================================================
# Limpeza
# ============================================================
.PHONY: clean clean-data clean-artifacts nuke
clean: ## Limpa cache Python
	@rm -rf __pycache__ .pytest_cache .ruff_cache
	@find . -type d -name "__pycache__" -prune -exec rm -rf {} \; 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true

clean-data: ## Remove datasets gerados
	@rm -rf "$(DATA_DIR)"

clean-artifacts: ## Remove artefatos de modelo
	@rm -rf "$(ARTIFACTS_DIR)"

nuke: clean clean-data clean-artifacts ## Remove tudo que foi gerado
	@echo "Workspace limpo (dados, artifacts e caches)."

# ============================================================
# Atalhos de alto nivel
# ============================================================
.PHONY: quickstart setup all run
quickstart: venv install ensure-dirs ## Setup inicial rapido com venv
	@echo "Ambiente pronto. Proximos passos:"
	@echo "  source $(VENV_DIR)/bin/activate"
	@echo "  make collect-all"
	@echo "  make merge-datasets"
	@echo "  make train"
	@echo "  make api"

setup: quickstart ## Um comando para preparar ambiente completo
	@echo "Setup concluido."

all: setup pipeline ## Um comando para setup + pipeline completo
	@echo "Tudo pronto: modelo treinado em $(ARTIFACTS_DIR)."

run: api ## Alias para rodar API

