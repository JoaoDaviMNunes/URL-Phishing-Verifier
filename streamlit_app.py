from __future__ import annotations

import os
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from url_phishing_verifier.model.predictor import URLPhishingPredictor


@st.cache_resource
def load_predictor() -> URLPhishingPredictor:
    artifacts_dir = os.environ.get("MODEL_ARTIFACTS_DIR", "artifacts")
    return URLPhishingPredictor(artifacts_dir=artifacts_dir)


def main() -> None:
    st.set_page_config(page_title="URL Phishing Verifier", layout="wide")
    st.title("URL Phishing Verifier")

    predictor = load_predictor()

    with st.expander("Explicabilidade (global - SHAP)", expanded=False):
        shap_top = predictor.metadata.get("shap", {}).get("top_features", [])
        if shap_top:
            df_top = pd.DataFrame(shap_top)
            st.dataframe(df_top, use_container_width=True)
        else:
            st.info("Sem dados globais de SHAP ainda. Execute o treino para gerar.")

    st.subheader("Analisar URL")
    url = st.text_area("Cole a URL aqui", height=90, placeholder="ex: https://example.com/login?...")

    col1, col2, col3 = st.columns(3)
    with col1:
        enable_ssl = st.checkbox("Habilitar SSL", value=False)
    with col2:
        enable_geo = st.checkbox("Habilitar Geo", value=False)
    with col3:
        geo_method = st.selectbox("Geo method", ["dns_api", "ccTLD"], index=0)

    top_k = st.slider("Top SHAP features", min_value=3, max_value=15, value=8, step=1)

    if st.button("Analisar", type="primary", disabled=not url.strip()):
        with st.spinner("Extraindo features e fazendo inferência..."):
            result = predictor.predict(
                url=url,
                enable_ssl=enable_ssl,
                enable_geo=enable_geo,
                geo_method=geo_method,
                top_k_shap=top_k,
            )

        left, right = st.columns([1, 1])
        with left:
            st.markdown(f"**Classificação:** {result.risk_class}")
            st.markdown(f"**Score (0-100):** {result.score_0_100:.2f}")
            st.markdown(f"**Segmento:** {result.score_segment_label}")
            st.markdown(f"**Probabilidade phishing:** {result.prob_phishing:.4f}")
            if result.country_cc:
                st.markdown(f"**País (ccTLD/DNS):** {result.country_cc}")
                st.markdown(f"**Risco por região:** {result.country_risk:.3f}")
                st.markdown(f"**Método:** {result.country_method}")
            else:
                st.caption("Geolocalização desabilitada ou indisponível (habilite `Geo`).")

            score_pct = max(0.0, min(1.0, result.score_0_100 / 100.0))
            st.progress(int(score_pct * 100))

        with right:
            st.markdown("**Explicação (SHAP - instância)**")
            if result.top_shap_features:
                df_shap = pd.DataFrame(result.top_shap_features)
                st.dataframe(
                    df_shap[["feature", "shap_value", "abs_shap"]].rename(
                        columns={"shap_value": "shap_value", "abs_shap": "|shap|"}
                    ),
                    use_container_width=True,
                )
            else:
                st.info("Sem SHAP na inferência (talvez por compatibilidade/erro).")


if __name__ == "__main__":
    main()

