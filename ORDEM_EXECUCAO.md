# Ordem de Execução dos Códigos

> **Contexto:** Os arquivos de dados brutos (`data/raw/`) já foram coletados da internet e tratados. Não é necessário realizar a etapa de coleta novamente.

## Passo a Passo Simplificado

1. **Unificar os Dados** *(necessário apenas se você precisar recriar o dataset)*
   > Se o arquivo `data/processed/dataset.csv` já existir, pule para o passo 2.

   ```bash
   python3 scripts/merge_datasets.py \
     --inputs data/raw/legit_alexa.csv data/raw/phishing_mendeley.csv data/raw/phishing_phishtank.csv \
     --out data/processed/dataset.csv
   ```

2. **Treinar o Modelo** — Ensina o computador a identificar URLs de phishing:
   ```bash
   python3 scripts/train_model.py \
     --csv data/processed/dataset.csv \
     --artifacts-dir artifacts
   ```

3. **Rodar o Site (Local)** — Abre a interface visual para testar URLs:
   ```bash
   streamlit run streamlit_app.py
   ```

## Verificações Externas (opcional)

Para habilitar verificações com APIs externas, configure as variáveis de ambiente antes de rodar:

```bash
export VIRUSTOTAL_API_KEY="sua_chave_aqui"
export GOOGLE_SAFEBROWSING_KEY="sua_chave_aqui"
```

Sem estas chaves, as verificações do Cloudflare Radar e ESET continuam funcionando normalmente.

## Banco de Dados

Todas as análises são salvas automaticamente em `data/url_cache.db` (SQLite). Ao pesquisar uma URL já analisada, o resultado será carregado instantaneamente do cache, com opção de verificar novamente.

---
**Dica:** Use `make train` para treinar e `make dashboard` para subir o site!
