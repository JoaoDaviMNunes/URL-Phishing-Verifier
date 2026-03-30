# URL-Phishing-Verifier

Verificador de phishing em URLs com **dupla verificação**: banco de dados + análise em tempo real (LightGBM + SHAP + verificações externas).

## Como funciona

Ao colar uma URL, o sistema sempre exibe **dois resultados lado a lado**:

```
┌─────────────────────┐  ┌─────────────────────┐
│  📂 Banco de Dados  │  │  🔬 Análise em      │
│                     │  │     Tempo Real       │
│  ✅ Seguro          │  │  ✅ Seguro           │
│  98.2% confiança    │  │  97.5% confiança     │
└─────────────────────┘  └─────────────────────┘
         ┌─────────────────────┐
         │  ⚖️ Veredicto Final │
         │  ✅ Ambas as fontes  │
         │  indicam segurança   │
         └─────────────────────┘
```

- **Banco de Dados**: mostra resultado de análise anterior (se existir)
- **Análise em Tempo Real**: sempre executa o modelo de IA + verificações externas
- **Veredicto Final**: compara ambas as fontes e informa se concordam ou divergem

## Visão geral do pipeline

1. **Datasets pré-tratados (já disponíveis em `data/raw/`)**
   - **PhishTank** (`phishing_phishtank.csv`) — URLs maliciosas
   - **Mendeley Phishing Dataset** (`phishing_mendeley.csv`) — URLs maliciosas
   - **Alexa Top Sites** (`legit_alexa.csv`) — URLs legítimas

2. **Extração de features (25 features)**
   - **Lexicais**: comprimento, entropia de Shannon, dígitos excessivos, palavras suspeitas (`login`, `verify`, `paypal`, etc.)
   - **Estruturais**: `tldextract` (domínio vs subdomínio), detecção de IP como host, URL encurtada
   - **SSL**: presença de HTTPS, validade e idade do certificado
   - **Geolocalização**: risco por região (ccTLD e/ou DNS+API)

3. **Modelagem**
   - **LightGBM** (classificação binária: phishing=1, seguro=0)
   - Treinado com **1.235.370 URLs** reais
   - Threshold otimizado via **F-beta (β=2.0)** para reduzir falsos negativos
   - Accuracy: **99.96%** · ROC-AUC: **99.98%** · Recall: **99.94%**

4. **Explicabilidade**
   - **SHAP values** por instância: mostra quais features da URL mais influenciaram o resultado
   - Tabela com impacto (🔴 aumenta risco / 🟢 reduz risco) e score numérico

5. **Verificações Externas (4 fontes)**
   - **Cloudflare Radar** — reputação do domínio
   - **ESET Link Checker** — scanner de malware
   - **VirusTotal** — agregador de antivírus (requer API key)
   - **Google Safe Browsing** — blacklist do Google (requer API key)

6. **Persistência**
   - **SQLite** (`data/url_cache.db`) — salva cada análise automaticamente
   - Na próxima consulta, o resultado do banco aparece ao lado de uma nova análise em tempo real

## Pré-requisitos

```bash
python3 -m pip install -r requirements.txt
```

## Execução rápida

```bash
# 1. Treinar o modelo (necessário apenas uma vez)
make train

# 2. Rodar o dashboard
make dashboard
```

Ou manualmente:

```bash
# Treinar
python3 scripts/train_model.py \
  --csv data/processed/dataset.csv \
  --artifacts-dir artifacts

# Dashboard
streamlit run streamlit_app.py
```

## Execução com Makefile (recomendado)

O projeto usa **Python3** e ambiente virtual **`venv-url`**.

```bash
make help          # mostra todos os comandos
make setup         # prepara tudo (venv + deps + pastas)
make all           # setup + pipeline completo (merge + treino)
make dashboard     # roda o site
make api           # roda a API FastAPI
```

## Verificações externas (APIs opcionais)

Para habilitar VirusTotal e Google Safe Browsing:

```bash
export VIRUSTOTAL_API_KEY="sua_chave_aqui"
export GOOGLE_SAFEBROWSING_KEY="sua_chave_aqui"
```

Sem estas chaves, Cloudflare Radar e ESET continuam funcionando normalmente.

## Estrutura do projeto

```
├── streamlit_app.py              # Dashboard (interface principal)
├── url_phishing_verifier/
│   ├── model/
│   │   ├── predictor.py          # Predição com LightGBM + SHAP
│   │   └── trainer.py            # Treino do modelo
│   ├── features/
│   │   ├── extractor.py          # Orquestrador de features
│   │   ├── lexical.py            # Features lexicais (entropia, dígitos, etc.)
│   │   ├── structural.py         # Features estruturais (domínio, subdomínios)
│   │   ├── ssl.py                # Features de certificado SSL
│   │   ├── geolocation.py        # Features de geolocalização
│   │   └── external_checks.py    # Verificações externas (CF, ESET, VT, GSB)
│   ├── data/
│   │   ├── database.py           # Cache SQLite
│   │   └── io.py                 # Loader de datasets CSV
│   └── api/
│       ├── app.py                # API FastAPI
│       └── schemas.py            # Schemas Pydantic
├── scripts/                      # Scripts de coleta, merge e treino
├── artifacts/                    # Modelo treinado + metadados
├── data/                         # Datasets e cache
├── Makefile                      # Automação
├── ORDEM_EXECUCAO.md             # Guia simplificado de execução
└── requirements.txt              # Dependências Python
```

## Coleta de dados (scripts)

Os scripts geram CSVs rotulados (`url,label`):

```bash
# PhishTank
python3 scripts/collect_phishtank.py \
  --dump-url-or-path "data/raw/phish_dump.txt" \
  --out "data/raw/phishing_phishtank.csv" \
  --limit 50000

# Mendeley
python3 scripts/collect_mendeley_phishing.py \
  --input "data/raw/mendeley_phishing.csv" \
  --out "data/raw/phishing_mendeley.csv" \
  --url-column url

# Alexa Top Sites
python3 scripts/collect_alexa_legit.py \
  --input "data/raw/alexa_top_sites.csv" \
  --out "data/raw/legit_alexa.csv" \
  --domain-column domain

# Merge
python3 scripts/merge_datasets.py \
  --inputs "data/raw/phishing_phishtank.csv" "data/raw/phishing_mendeley.csv" "data/raw/legit_alexa.csv" \
  --out "data/processed/dataset.csv"
```

## Treino do modelo

```bash
# Treino básico
python3 scripts/train_model.py \
  --csv "data/processed/dataset.csv" \
  --artifacts-dir "artifacts" \
  --beta-fbeta 2.0

# Com features SSL + Geo (mais lento)
python3 scripts/train_model.py \
  --csv "data/processed/dataset.csv" \
  --artifacts-dir "artifacts" \
  --enable-ssl --enable-geo --geo-method dns_api
```

## Artefatos gerados

Após o treino:
- `artifacts/model.joblib` — modelo treinado
- `artifacts/metadata.json` — métricas, threshold, feature importance, SHAP global

## API (FastAPI)

```bash
python3 scripts/run_api.py
```

Endpoint: `POST /analyze` — body: `{"url": "https://...", "enable_ssl": true, "enable_geo": true}`
