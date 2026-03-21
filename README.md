# URL-Phishing-Verifier
Verificador de phishing em URLs (LightGBM + features lexicais/estruturais/SSL/Geo + API + dashboard).

## Visão geral do pipeline
1. **Datasets pré-tratados (já disponíveis em `data/raw/`)**  
   - **PhishTank** (`phishing_phishtank.csv`) — maliciosas  
   - **Mendeley Phishing Dataset** (`phishing_mendeley.csv`) — maliciosas  
   - **Alexa Top Sites** (`legit_alexa.csv`) — legítimas

2. **Extração de features**
   - **Lexicais**: regex (ex.: `@`, `-`, palavras suspeitas), tamanho, dígitos excessivos, **entropia**.
   - **Estruturais**: `tldextract` (domínio vs subdomínio), detecção de **IP** como host, **URL encurtada**.
   - **SSL (opcional)**: HTTPS, certificado (validade e idade).
   - **Geolocalização (opcional)**: risco por região (ccTLD e/ou DNS+API).

3. **Modelagem**
   - **LightGBM** (classificação binária: phishing=1, seguro=0).
   - Para cumprir a saída pedida, convertemos a probabilidade em:
     - **score 0-100** (probabilidade * 100)
     - **Classificação** (`Seguro`/`Suspeito`/`Malicioso`) usando o `best_threshold` aprendido no treino (reduz falso negativo).
     - **score_segment_label** usa as faixas do enunciado: `Seguro`, `Saudável`, `Atenção`, `Perigoso`, `Crítico`.

4. **Avaliação (com foco em reduzir falso negativo)**
   - Métricas: `Accuracy`, `Precision`, `Recall`, `F1-score`, `ROC-AUC`
   - Threshold escolhido com **F-beta (beta>1)** para privilegiar recall (reduzir falso negativo).
   - Resultados e artefatos ficam em `artifacts/metadata.json`.

5. **Explicabilidade**
   - **Feature importance** do LightGBM (global)
   - **SHAP values**
     - Global: Top features por `mean(|SHAP|)`
     - Instância: top contribuições SHAP retornadas na API/dash

6. **Funcionalidades**
   - **API**: FastAPI (`POST /analyze`) recebe `url` e devolve classificação + score (+ top SHAP).
   - **Dashboard**: Streamlit (cola URL e visualiza resultado).

## Pré-requisitos
```bash
python3 -m pip install -r requirements.txt
```

## Execução com Makefile (recomendado)
O projeto já está preparado para usar **Python3** e ambiente virtual chamado **`venv-url`**.

```bash
# mostra todos os comandos
make help

# comando simples 1: prepara tudo (venv + deps + pastas)
make setup

# comando simples 2: faz setup + pipeline completo (coleta, merge, treino)
make all
```

Comandos úteis:
```bash
# cria/recria venv-url
make venv
make venv-recreate

# instala dependências no venv
make install

# roda API e dashboard
make api
make dashboard
```

Se quiser ativar manualmente no shell:
```bash
source venv-url/bin/activate
```

## Estrutura de dataset (obrigatório)
Antes do treino, gere um `dataset.csv` com:
- coluna `url`
- coluna `label` (0=Seguro/Legítimo, 1=Phishing/Malicioso)

## Coleta de dados (scripts)
Os scripts abaixo geram CSVs rotulados (`url,label`). Para PhishTank e Mendeley, o formato real do arquivo pode variar, então os coletores são “robustos” e aceitam:
- arquivo local, ou
- dump/feed em texto via URL HTTP.

Exemplos (ajuste paths/colunas conforme seu dataset):

```bash
# PhishTank (dump/feed de texto)
python3 scripts/collect_phishtank.py \
  --dump-url-or-path "data/raw/phish_dump.txt" \
  --out "data/raw/phishing_phishtank.csv" \
  --limit 50000

# Mendeley (CSV/TSV local)
python3 scripts/collect_mendeley_phishing.py \
  --input "data/raw/mendeley_phishing.csv" \
  --out "data/raw/phishing_mendeley.csv" \
  --url-column url

# Alexa Top Sites (CSV ou TXT com domínio)
python3 scripts/collect_alexa_legit.py \
  --input "data/raw/alexa_top_sites.csv" \
  --out "data/raw/legit_alexa.csv" \
  --domain-column domain

# Merge final (se necessário recriar o dataset processado)
python3 scripts/merge_datasets.py \
  --inputs "data/raw/phishing_phishtank.csv" "data/raw/phishing_mendeley.csv" "data/raw/legit_alexa.csv" \
  --out "data/processed/dataset.csv"
```

As mesmas etapas via `make`:
```bash
make collect-phishtank
make collect-mendeley MENDELEY_INPUT=/caminho/mendeley.csv
make collect-alexa ALEXA_INPUT=/caminho/alexa.csv
make merge-datasets
```

Observação:
- Se um arquivo de coleta não existir, o `Makefile` gera um CSV vazio com aviso (`[WARN]`) para o fluxo não quebrar com traceback.
- Para obter dados reais, sempre informe os caminhos corretos (`PHISHTANK_DUMP`, `MENDELEY_INPUT`, `ALEXA_INPUT`).

## Treino do modelo
```bash
python3 scripts/train_model.py \
  --csv "data/processed/dataset.csv" \
  --artifacts-dir "artifacts" \
  --beta-fbeta 2.0
```

Se quiser incluir features **SSL**/ **Geo** (pode ser lento):
```bash
python3 scripts/train_model.py \
  --csv "data/processed/dataset.csv" \
  --artifacts-dir "artifacts" \
  --enable-ssl \
  --enable-geo \
  --geo-method dns_api
```

## Métricas e artefatos
Após o treino:
- `artifacts/model.joblib` (modelo)
- `artifacts/metadata.json` (métricas, threshold, feature importance, SHAP global, nomes das features)

## API (FastAPI)
1. Garanta que `artifacts/` existe (rodou o treino).
2. Suba a API:
```bash
python3 scripts/run_api.py
```
Endpoint:
- `POST /analyze`  
  body:
  - `url` (string)
  - `enable_ssl` (bool, opcional)
  - `enable_geo` (bool, opcional)

## Dashboard (Streamlit)
```bash
streamlit run streamlit_app.py
```
O dashboard permite:
- colar URL
- opcionalmente habilitar SSL/Geo
- visualizar `risk_class`, `score_0_100` e top contribuições SHAP.
