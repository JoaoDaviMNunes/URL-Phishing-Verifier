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

## Como funciona a análise

Ao digitar uma URL, o sistema consulta **duas fontes independentes** e exibe ambos os resultados lado a lado:

| Fonte | O que faz | Quando aparece |
|-------|-----------|----------------|
| **📂 Banco de Dados** | Busca análises anteriores já realizadas para aquela URL | Se a URL já foi analisada antes |
| **🔬 Análise em Tempo Real** | Executa o modelo de IA (LightGBM) + verificações externas (Cloudflare, ESET, VirusTotal, Google) | **Sempre** — toda URL é analisada do zero |

Após exibir as duas fontes, um **⚖️ Veredicto Final** compara ambas:
- ✅ Se ambas concordam que é seguro → confiança alta
- 🚨 Se ambas concordam que é perigoso → alerta forte
- ⚠️ Se divergem → recomenda cautela

### Detalhes técnicos expandíveis

Abaixo do veredicto, uma seção expansível mostra:
- **Dados Básicos** — domínio, IP, país de origem, título da página
- **Estrutura da URL** — protocolo, subdomínios, comprimento, palavras suspeitas
- **Verificações Externas** — resultado de cada fonte (Cloudflare Radar, ESET, VirusTotal, Google Safe Browsing)
- **SHAP** — quais características da URL mais influenciaram o resultado da IA

## Verificações Externas (opcional)

Para habilitar verificações com APIs externas, configure as variáveis de ambiente antes de rodar:

```bash
export VIRUSTOTAL_API_KEY="sua_chave_aqui"
export GOOGLE_SAFEBROWSING_KEY="sua_chave_aqui"
```

Sem estas chaves, as verificações do Cloudflare Radar e ESET continuam funcionando normalmente.

## Banco de Dados

Todas as análises são salvas automaticamente em `data/url_cache.db` (SQLite). Na próxima consulta da mesma URL, o resultado do banco aparecerá na coluna "📂 Banco de Dados", ao lado de uma nova análise em tempo real.

---
**Dica:** Use `make train` para treinar e `make dashboard` para subir o site!
