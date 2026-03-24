from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import pandas as pd
import streamlit as st
import tldextract

from url_phishing_verifier.data.database import lookup_url, save_result
from url_phishing_verifier.features.external_checks import (
    ExternalCheckResult,
    PageMetadata,
    run_all_external_checks,
)
from url_phishing_verifier.model.predictor import URLPhishingPredictor


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Predictor loader
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@st.cache_resource
def load_predictor() -> URLPhishingPredictor | None:
    artifacts_dir = os.environ.get("MODEL_ARTIFACTS_DIR", "artifacts")
    try:
        return URLPhishingPredictor(artifacts_dir=artifacts_dir)
    except FileNotFoundError:
        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  i18n / Traduções
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TRANSLATIONS = {
    "Português": {
        "title": "🛡️ URL Phishing Verifier",
        "subtitle": "Verifique a segurança de qualquer link em segundos. Nossa IA analisa a estrutura da URL e consulta múltiplas fontes externas.",
        "input_label": "🔗 Cole a URL e pressione Enter para analisar",
        "input_placeholder": "Ex: https://site-suspeito.com/login?redirect=paypal",
        "input_help": "Digite uma URL e pressione Enter para iniciar a análise.",
        "btn_recheck": "🔄 Verificar novamente",
        "found_db": "📂 Resultado encontrado no nosso banco de dados.",
        "analyzed_at": "Análise realizada em",
        "progress_starting": "Iniciando análise...",
        "progress_ai": "Analisando features da URL com IA...",
        "progress_external_start": "Modelo IA concluído. Iniciando verificações externas...",
        "progress_finishing": "Finalizando análise...",
        "progress_done": "Análise concluída!",
        "risk_safe": "Seguro",
        "risk_suspicious": "Suspeito",
        "risk_malicious": "Malicioso",
        "conf_label": "confiança",
        "risk_label": "risco",
        "detected_origin": "📍 Origem detectada",
        "basic_data_title": "📋 Dados Básicos",
        "domain": "Domínio",
        "origin_country": "País de Origem",
        "ip": "IP",
        "page_title": "Título da Página",
        "technologies": "Tecnologias",
        "url_structure_title": "🔎 Estrutura da URL",
        "protocol": "Protocolo",
        "subdomain": "Subdomínio",
        "tld": "TLD",
        "path": "Caminho",
        "params": "Parâmetros",
        "length": "Comprimento",
        "ip_as_host": "IP como host",
        "short_url": "URL encurtada",
        "at_symbol": "@ na URL",
        "total_sub": "níveis",
        "suspicious_words": "Palavras suspeitas",
        "external_checks_title": "🌐 Verificações Externas",
        "legend_external": "🟢 Seguro · 🔴 Malicioso · ⚪ Indisponível",
        "shap_title": "🧠 Por que este resultado?",
        "shap_legend": "🔴 aumenta risco de phishing · 🟢 reduz risco de phishing",
        "about_title": "ℹ️ Sobre o URL Phishing Verifier",
        "about_content": "Utiliza **LightGBM** treinado em mais de 1,2 milhão de URLs reais, combinado com verificações externas e SHAP para transparência.",
        "none": "(nenhum)",
        "not_identified": "(não identificado)",
        "not_resolved": "(não resolvido)",
        "no_params": "(sem parâmetros)",
        "root": "(raiz)",
        "config_title": "⚙️ Configurações de Análise",
        "ver_ssl": "Verificar SSL",
        "ver_geo": "Geolocalização",
        "geo_method": "Método Geo",
        "shap_count": "Features SHAP",
    },
    "English": {
        "title": "🛡️ URL Phishing Verifier",
        "subtitle": "Verify the safety of any link in seconds. Our AI analyzes URL structure and queries multiple external sources.",
        "input_label": "🔗 Paste the URL and press Enter to analyze",
        "input_placeholder": "E.g.: https://site-suspeito.com/login?redirect=paypal",
        "input_help": "Type a URL and press Enter to start the analysis.",
        "btn_recheck": "🔄 Verify again",
        "found_db": "📂 Result found in our database.",
        "analyzed_at": "Analysis performed at",
        "progress_starting": "Starting analysis...",
        "progress_ai": "Analyzing URL features with AI...",
        "progress_external_start": "AI model complete. Starting external checks...",
        "progress_finishing": "Finishing analysis...",
        "progress_done": "Analysis complete!",
        "risk_safe": "Safe",
        "risk_suspicious": "Suspicious",
        "risk_malicious": "Malicious",
        "conf_label": "confidence",
        "risk_label": "risk",
        "detected_origin": "📍 Detected origin",
        "basic_data_title": "📋 Basic Data",
        "domain": "Domain",
        "origin_country": "Country of Origin",
        "ip": "IP",
        "page_title": "Page Title",
        "technologies": "Technologies",
        "url_structure_title": "🔎 URL Structure",
        "protocol": "Protocol",
        "subdomain": "Subdomain",
        "tld": "TLD",
        "path": "Path",
        "params": "Parameters",
        "length": "Length",
        "ip_as_host": "IP as host",
        "short_url": "Shortened URL",
        "at_symbol": "@ in URL",
        "total_sub": "levels",
        "suspicious_words": "Suspicious words",
        "external_checks_title": "🌐 External Verifications",
        "legend_external": "🟢 Safe · 🔴 Malicious · ⚪ Unavailable",
        "shap_title": "🧠 Why this result?",
        "shap_legend": "🔴 increases phishing risk · 🟢 reduces phishing risk",
        "about_title": "ℹ️ About URL Phishing Verifier",
        "about_content": "Uses **LightGBM** trained on 1.2M+ URLs, combined with external checks and SHAP for transparency.",
        "none": "(none)",
        "not_identified": "(not identified)",
        "not_resolved": "(not resolved)",
        "no_params": "(no parameters)",
        "root": "(root)",
        "config_title": "⚙️ Analysis Settings",
        "ver_ssl": "Verify SSL",
        "ver_geo": "Geolocation",
        "geo_method": "Geo Method",
        "shap_count": "SHAP features",
    }
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CSS — Cyber-Industrial Design System
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def apply_style():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    :root {
        --primary:    #22d3ee;
        --primary-dim: rgba(34,211,238,0.12);
        --primary-glow: rgba(34,211,238,0.25);
        --danger:     #fb7185;
        --danger-dim: rgba(251,113,133,0.12);
        --warning:    #fbbf24;
        --warning-dim: rgba(251,191,36,0.12);
        --safe:       #34d399;
        --safe-dim:   rgba(52,211,153,0.12);
        --bg:         #0a0e1a;
        --bg-elevated: #0f1629;
        --card-bg:    rgba(15,22,41,0.75);
        --card-border: rgba(34,211,238,0.08);
        --border:     rgba(255,255,255,0.06);
        --text:       #e2e8f0;
        --text-secondary: #94a3b8;
        --muted:      #64748b;
        --font-display: 'Space Grotesk', system-ui, sans-serif;
        --font-mono:   'JetBrains Mono', 'Fira Code', monospace;
    }

    /* ── Typography ── */
    html, body, [class*="css"] {
        font-family: var(--font-display) !important;
        color: var(--text) !important;
    }

    h1 {
        font-family: var(--font-display) !important;
        color: var(--primary) !important;
        font-weight: 700 !important;
        letter-spacing: -0.03em;
        font-size: 2.2rem !important;
        text-shadow: 0 0 40px var(--primary-glow), 0 0 80px rgba(34,211,238,0.08);
        position: relative;
    }
    h2, h3 {
        font-family: var(--font-display) !important;
        color: var(--text) !important;
        font-weight: 600 !important;
        letter-spacing: -0.02em;
    }

    /* ── Animated scan-line on app header ── */
    .scan-header {
        position: relative;
        overflow: hidden;
        padding: 2rem 0 1rem;
        margin-bottom: 0.5rem;
    }
    .scan-header::after {
        content: '';
        position: absolute;
        top: 0; left: -100%; right: 0; bottom: 0;
        background: linear-gradient(
            90deg,
            transparent 0%,
            rgba(34,211,238,0.04) 40%,
            rgba(34,211,238,0.08) 50%,
            rgba(34,211,238,0.04) 60%,
            transparent 100%
        );
        animation: scanline 4s ease-in-out infinite;
        pointer-events: none;
    }
    @keyframes scanline {
        0%   { transform: translateX(0); }
        100% { transform: translateX(200%); }
    }
    .scan-subtitle {
        font-family: var(--font-mono) !important;
        font-size: 0.85rem;
        color: var(--text-secondary);
        letter-spacing: 0.02em;
        line-height: 1.6;
        margin-top: 0.25rem;
    }

    /* ── Grain overlay for texture ── */
    .main .block-container::before {
        content: '';
        position: fixed;
        top: 0; left: 0; width: 100vw; height: 100vh;
        background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.03'/%3E%3C/svg%3E");
        pointer-events: none;
        z-index: 0;
    }

    /* ── Input field ── */
    .stTextInput input {
        background: var(--bg-elevated) !important;
        color: #fff !important;
        border: 1.5px solid var(--card-border) !important;
        border-radius: 12px !important;
        font-family: var(--font-mono) !important;
        font-size: 0.95rem !important;
        padding: 0.85rem 1.1rem !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
    }
    .stTextInput input:focus {
        border-color: var(--primary) !important;
        box-shadow: 0 0 0 3px var(--primary-dim),
                    0 0 20px rgba(34,211,238,0.1) !important;
    }
    .stTextInput label {
        font-family: var(--font-display) !important;
        font-weight: 500 !important;
        letter-spacing: 0.01em;
    }

    /* ── Buttons ── */
    div.stButton > button:first-child {
        background: linear-gradient(135deg, #22d3ee 0%, #06b6d4 50%, #0891b2 100%) !important;
        color: #0a0e1a !important;
        font-family: var(--font-display) !important;
        font-weight: 600 !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.7rem 2.5rem !important;
        font-size: 0.95rem !important;
        letter-spacing: 0.02em;
        width: 100%;
        transition: all 0.2s ease !important;
        box-shadow: 0 4px 15px rgba(34,211,238,0.2) !important;
    }
    div.stButton > button:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 25px rgba(34,211,238,0.3) !important;
    }

    /* ── Risk Badges — pulsing shield ── */
    @keyframes pulse-safe {
        0%, 100% { box-shadow: 0 0 0 0 rgba(52,211,153,0.4); }
        50%      { box-shadow: 0 0 0 12px rgba(52,211,153,0); }
    }
    @keyframes pulse-warn {
        0%, 100% { box-shadow: 0 0 0 0 rgba(251,191,36,0.4); }
        50%      { box-shadow: 0 0 0 12px rgba(251,191,36,0); }
    }
    @keyframes pulse-danger {
        0%, 100% { box-shadow: 0 0 0 0 rgba(251,113,133,0.5); }
        50%      { box-shadow: 0 0 0 14px rgba(251,113,133,0); }
    }
    .badge {
        display: inline-flex; align-items: center; gap: 0.6rem;
        padding: 0.7rem 2rem;
        border-radius: 999px;
        font-family: var(--font-display) !important;
        font-weight: 700;
        font-size: 1.2rem;
        text-align: center;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        transition: transform 0.2s ease;
    }
    .badge:hover { transform: scale(1.03); }
    .badge-ok {
        background: var(--safe-dim);
        color: var(--safe);
        border: 2px solid var(--safe);
        animation: pulse-safe 2.5s ease-out infinite;
    }
    .badge-warn {
        background: var(--warning-dim);
        color: var(--warning);
        border: 2px solid var(--warning);
        animation: pulse-warn 2s ease-out infinite;
    }
    .badge-bad {
        background: var(--danger-dim);
        color: var(--danger);
        border: 2px solid var(--danger);
        animation: pulse-danger 1.5s ease-out infinite;
    }

    /* ── Glassmorphism Cards ── */
    .card {
        background: var(--card-bg);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid var(--card-border);
        border-radius: 16px;
        padding: 1.4rem 1.6rem;
        margin-bottom: 1.25rem;
        transition: border-color 0.3s ease, box-shadow 0.3s ease;
    }
    .card:hover {
        border-color: rgba(34,211,238,0.18);
        box-shadow: 0 4px 30px rgba(34,211,238,0.06);
    }
    .card-title {
        font-family: var(--font-mono) !important;
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--primary);
        margin-bottom: 0.85rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--border);
    }

    /* ── Chips ── */
    .chip {
        display: inline-block;
        padding: 0.2rem 0.65rem;
        border-radius: 6px;
        font-family: var(--font-mono) !important;
        font-size: 0.75rem;
        font-weight: 500;
        margin: 0.15rem 0.1rem;
        letter-spacing: 0.02em;
    }
    .chip-ok  { background: var(--safe-dim); color: var(--safe); }
    .chip-bad { background: var(--danger-dim); color: var(--danger); }
    .chip-neu { background: rgba(255,255,255,0.06); color: var(--text-secondary); }

    /* ── Confidence Bar ── */
    .conf-bar-track {
        background: rgba(255,255,255,0.06);
        border-radius: 999px;
        height: 10px;
        overflow: hidden;
        margin-top: 0.35rem;
        position: relative;
    }
    .conf-bar-fill {
        height: 100%;
        border-radius: 999px;
        transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
    }
    .conf-bar-fill::after {
        content: '';
        position: absolute;
        top: 0; right: 0; bottom: 0;
        width: 30px;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2));
        border-radius: 0 999px 999px 0;
    }
    .conf-label {
        font-family: var(--font-mono) !important;
        font-weight: 600;
        font-size: 1rem;
        margin-bottom: 0.2rem;
    }

    /* ── Source Note (cached result) ── */
    .source-note {
        background: var(--primary-dim);
        border: 1px solid rgba(34,211,238,0.2);
        border-left: 3px solid var(--primary);
        border-radius: 0 10px 10px 0;
        padding: 0.75rem 1.1rem;
        margin-bottom: 1rem;
        font-family: var(--font-mono) !important;
        font-size: 0.82rem;
        color: var(--primary);
    }

    /* ── External Check Rows ── */
    @keyframes fadeSlideIn {
        from { opacity: 0; transform: translateX(-8px); }
        to   { opacity: 1; transform: translateX(0); }
    }
    .ext-row {
        display: flex;
        align-items: center;
        gap: 0.7rem;
        padding: 0.45rem 0;
        border-bottom: 1px solid rgba(255,255,255,0.03);
        font-family: var(--font-display) !important;
        font-size: 0.88rem;
        animation: fadeSlideIn 0.4s ease forwards;
    }
    .ext-row:nth-child(1) { animation-delay: 0.05s; }
    .ext-row:nth-child(2) { animation-delay: 0.1s;  }
    .ext-row:nth-child(3) { animation-delay: 0.15s; }
    .ext-row:nth-child(4) { animation-delay: 0.2s;  }
    .ext-row:nth-child(5) { animation-delay: 0.25s; }
    .ext-icon { font-size: 1.1rem; flex-shrink: 0; }
    .ext-name { font-weight: 500; color: var(--text); }
    .ext-detail {
        font-family: var(--font-mono) !important;
        color: var(--muted);
        margin-left: auto;
        font-size: 0.8rem;
    }

    /* ── Data Table Rows ── */
    .card table td {
        font-family: var(--font-display) !important;
        vertical-align: top;
    }
    .card table td:first-child {
        font-family: var(--font-mono) !important;
        font-size: 0.8rem;
        color: var(--muted);
        white-space: nowrap;
        padding-right: 1rem;
    }
    .card table td b {
        color: var(--text);
    }
    .card table code {
        font-family: var(--font-mono) !important;
        background: rgba(255,255,255,0.04);
        padding: 0.15rem 0.4rem;
        border-radius: 4px;
        font-size: 0.82rem;
    }

    /* ── Streamlit overrides ── */
    .stExpander {
        border: 1px solid var(--card-border) !important;
        border-radius: 12px !important;
    }
    .stProgress > div > div {
        background: linear-gradient(90deg, var(--primary), #06b6d4) !important;
    }
    footer { visibility: hidden; }

    /* ── Language toggle ── */
    .lang-toggle {
        font-family: var(--font-mono) !important;
        font-size: 0.78rem;
        color: var(--text-secondary);
    }
    </style>
    """, unsafe_allow_html=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "account", "secure",
    "bank", "paypal", "amazon", "confirm", "password", "free",
    "winner", "prize", "click", "urgent", "suspended",
]

SHORTENED_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc",
}


def _parse_url_info(url: str) -> Dict[str, Any]:
    raw = url.strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "http://" + raw
    parsed = urlparse(raw)
    ext = tldextract.extract(raw)

    domain = ext.registered_domain or parsed.netloc
    subdomain = ext.subdomain or ""
    tld = ext.suffix or ""
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ext.domain or ""))
    is_https = parsed.scheme.lower() == "https"
    is_short = (ext.registered_domain or "").lower() in SHORTENED_DOMAINS
    found_kw = [w for w in SUSPICIOUS_WORDS if w in raw.lower()]
    num_sub = len([s for s in subdomain.split(".") if s]) if subdomain else 0

    return {
        "protocol": parsed.scheme.upper(),
        "domain": domain,
        "subdomain": subdomain or "(nenhum)",
        "tld": f".{tld}" if tld else "(desconhecido)",
        "path": parsed.path if parsed.path and parsed.path != "/" else "(raiz)",
        "query": parsed.query if parsed.query else "(sem parâmetros)",
        "is_https": is_https,
        "is_ip": is_ip,
        "is_shortened": is_short,
        "num_subdomains": num_sub,
        "has_at_symbol": "@" in raw,
        "has_dash_in_domain": "-" in (ext.domain or ""),
        "url_length": len(raw),
        "suspicious_keywords": found_kw,
    }


def _shap_adjusted_score(
    prob_phishing: float,
    risk_class: str,
    top_shap: List[Dict[str, Any]],
) -> float:
    """
    Ajusta o score de confiança usando o consenso SHAP.

    Lógica:
    - Se a classe for "Seguro" (prob < threshold), queremos medir a CONFIANÇA de que é seguro.
    - Se for "Suspeito" ou "Malicioso", queremos medir o RISCO.

    Ajuste:
    - Calcula a proporção do total SHAP que aponta na direção do veredicto.
    - Um consenso SHAP alto → confiança permanece alta.
    - Consenso baixo (muitos SHAPs contraditórios) → confiança é moderada.

    Retorna um valor de 0..100 representando risco (>50 = mais perigoso).
    """
    base_score = prob_phishing * 100.0

    if not top_shap:
        return base_score

    is_phishing_verdict = risk_class in ("Suspeito", "Malicioso")

    # SHAP positivo = aumenta risco; negativo = reduz risco
    total_abs = sum(abs(f["shap_value"]) for f in top_shap) or 1e-9
    shap_toward_phishing = sum(f["shap_value"] for f in top_shap if f["shap_value"] > 0)
    shap_toward_safe = abs(sum(f["shap_value"] for f in top_shap if f["shap_value"] < 0))

    if is_phishing_verdict:
        # Consenso = quanto do SHAP apoia que é phishing
        consensus = shap_toward_phishing / total_abs  # 0..1
    else:
        # Consenso = quanto do SHAP apoia que é seguro
        consensus = shap_toward_safe / total_abs  # 0..1

    # Peso SHAP: consenso 1.0 → 100%, consenso 0.5 → multiplicador neutro, consenso<0.5 → reduz
    # Formula: score_ajustado = base ± base * (consensus - 0.5) * 0.4
    adjustment = (consensus - 0.5) * 0.4  # range: -0.2 to +0.2

    if is_phishing_verdict:
        adjusted = base_score * (1 + adjustment)
    else:
        safety_score = 100.0 - base_score
        adjusted_safety = safety_score * (1 + adjustment)
        adjusted = 100.0 - adjusted_safety  # convert back to risk scale

    return max(0.0, min(100.0, adjusted))


def _confidence_html(score: float, risk_class: str, adjusted_score: float) -> str:
    if risk_class == "Seguro":
        pct = 100 - adjusted_score
        label = f"{pct:.1f}% de confiança — Seguro"
        color = "var(--safe)"
        gradient = "linear-gradient(90deg, #059669, #34d399)"
    elif risk_class == "Suspeito":
        pct = adjusted_score
        label = f"{pct:.1f}% de risco — Suspeito"
        color = "var(--warning)"
        gradient = "linear-gradient(90deg, #d97706, #fbbf24)"
    else:
        pct = adjusted_score
        label = f"{pct:.1f}% de risco — Malicioso"
        color = "var(--danger)"
        gradient = "linear-gradient(90deg, #e11d48, #fb7185)"
    return f"""
    <div class="conf-label" style="color:{color}">{label}</div>
    <div class="conf-bar-track">
        <div class="conf-bar-fill" style="width:{pct:.1f}%;background:{gradient};"></div>
    </div>"""



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Render sections
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _render_badge(risk_class: str, T: Dict[str, str]):
    icons = {T["risk_safe"]: "✅", T["risk_suspicious"]: "⚠️", T["risk_malicious"]: "🚨"}
    classes = {T["risk_safe"]: "badge-ok", T["risk_suspicious"]: "badge-warn", T["risk_malicious"]: "badge-bad"}
    icon = icons.get(risk_class, "❓")
    cls = classes.get(risk_class, "badge-warn")
    st.markdown(
        f"<div style='text-align:center;margin:1rem 0'>"
        f"<span class='badge {cls}'>{icon} {risk_class}</span></div>",
        unsafe_allow_html=True,
    )


def _render_dados_basicos(meta: Optional[PageMetadata], url_info: Dict[str, Any], T: Dict[str, str]):
    """Seção Dados Básicos: domínio, país, título, tecnologias."""
    title = T["not_identified"]
    country = T["not_identified"]
    ip_addr = T["not_resolved"]
    techs = []

    if meta:
        title = meta.title or T["none"]
        country = meta.country or T["not_identified"]
        ip_addr = meta.ip_address or T["not_resolved"]
        techs = meta.technologies or []

    # Destaque para País e Título (Requisito do Usuário)
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**📍 {T['origin_country']}:**")
        st.info(country)
    with c2:
        st.markdown(f"**📄 {T['page_title']}:**")
        st.info(title)

    rows = f"""
    <tr><td style="color:#8892a4;padding:5px 0;width:35%">{T['domain']}</td>
        <td><b>{url_info['domain']}</b></td></tr>
    <tr><td style="color:#8892a4;padding:5px 0">{T['ip']}</td>
        <td><code style="font-size:.85rem">{ip_addr}</code></td></tr>
    <tr><td style="color:#8892a4;padding:5px 0">{T['technologies']}</td>
        <td>{"".join(f"<span class='chip chip-neu'>{t}</span>" for t in techs) if techs else f"<span style='color:#8892a4'>{T['none']}</span>"}</td></tr>
    """

    st.markdown(f"""
    <div class="card">
        <div class="card-title">{T['basic_data_title']}</div>
        <table style="width:100%;border-collapse:collapse;font-size:.88rem">{rows}</table>
    </div>""", unsafe_allow_html=True)


def _render_url_details(info: Dict[str, Any], T: Dict[str, str]):
    """Seção detalhes da URL (estrutura)."""
    kws = info["suspicious_keywords"]
    st.markdown(f"""
    <div class="card">
        <div class="card-title">{T['url_structure_title']}</div>
        <table style="width:100%;border-collapse:collapse;font-size:.88rem">
            <tr><td style="color:#8892a4;padding:4px 0;width:35%">{T['protocol']}</td>
                <td><b>{info['protocol']}</b>
                    {"&nbsp;<span class='chip chip-ok'>HTTPS ✓</span>" if info['is_https'] else "&nbsp;<span class='chip chip-bad'>HTTP ⚠</span>"}</td></tr>
            <tr><td style="color:#8892a4;padding:4px 0">{T['subdomain']}</td>
                <td>{info['subdomain']}
                    {"&nbsp;<span class='chip chip-bad'>"+str(info['num_subdomains'])+" "+T['total_sub']+" ⚠</span>" if info['num_subdomains']>2 else ""}</td></tr>
            <tr><td style="color:#8892a4;padding:4px 0">{T['tld']}</td>
                <td>{info['tld']}</td></tr>
            <tr><td style="color:#8892a4;padding:4px 0">{T['path']}</td>
                <td style="word-break:break-all">{info['path'] if info['path'] != '(raiz)' else T['root']}</td></tr>
            <tr><td style="color:#8892a4;padding:4px 0">{T['params']}</td>
                <td style="word-break:break-all">{info['query'] if info['query'] != '(sem parâmetros)' else T['no_params']}</td></tr>
            <tr><td style="color:#8892a4;padding:4px 0">{T['length']}</td>
                <td>{info['url_length']}
                    {"&nbsp;<span class='chip chip-bad'>⚠</span>" if info['url_length']>75 else ""}</td></tr>
            <tr><td style="color:#8892a4;padding:4px 0">{T['ip_as_host']}</td>
                <td>{"<span class='chip chip-bad'>⚠</span>" if info['is_ip'] else "No"}</td></tr>
            <tr><td style="color:#8892a4;padding:4px 0">{T['short_url']}</td>
                <td>{"<span class='chip chip-bad'>⚠</span>" if info['is_shortened'] else "No"}</td></tr>
            <tr><td style="color:#8892a4;padding:4px 0">{T['at_symbol']}</td>
                <td>{"<span class='chip chip-bad'>⚠</span>" if info['has_at_symbol'] else "No"}</td></tr>
        </table>
        {"<div style='margin-top:.7rem'><span style='color:#8892a4;font-size:.8rem'>⚠️ "+T['suspicious_words']+":</span> "+" ".join(f"<span class='chip chip-bad'>{w}</span>" for w in kws)+"</div>" if kws else ""}
    </div>""", unsafe_allow_html=True)


def _render_external_checks(results: List[ExternalCheckResult], T: Dict[str, str]):
    """Seção de verificações externas — glassmorphism card with animated rows."""
    if not results:
        return

    rows_html = ""
    for r in results:
        if r.safe is True:
            icon = "🟢"
        elif r.safe is False:
            icon = "🔴"
        else:
            icon = "⚪"
        rows_html += f"""
        <div class="ext-row">
            <span class="ext-icon">{icon}</span>
            <span class="ext-name">{r.source}</span>
            <span class="ext-detail">{r.details}</span>
        </div>"""

    st.markdown(f"""
    <div class="card">
        <div class="card-title">{T['external_checks_title']}</div>
        {rows_html}
        <div style="margin-top:.7rem;font-size:.72rem;color:var(--muted);font-family:var(--font-mono)">
            {T['legend_external']}
        </div>
    </div>""", unsafe_allow_html=True)


def _render_shap(top_shap: List[Dict[str, Any]], T: Dict[str, str], lang: str):
    """Seção de explicabilidade SHAP — usando st.dataframe para evitar problemas de renderização HTML."""
    if not top_shap:
        return

    _FEATURE_LABELS_PT: Dict[str, str] = {
        "url_length": "Comprimento da URL",
        "url_entropy": "Entropia da URL",
        "num_digits": "Nº de dígitos",
        "digits_ratio": "Proporção de dígitos",
        "has_at": "Símbolo @",
        "has_dash": "Traço no domínio",
        "has_question_mark": "Ponto de interrogação",
        "has_suspicious_words": "Palavras suspeitas",
        "suspicious_words_count": "Qtd. palavras suspeitas",
        "excessive_digits": "Dígitos excessivos",
        "num_subdomains": "Nº de subdomínios",
        "subdomain_length": "Comprimento do subdomínio",
        "domain_length": "Comprimento do domínio",
        "suffix_length": "Comprimento do sufixo",
        "is_ip_address": "IP como endereço",
        "is_shortened_url": "URL encurtada",
        "has_path": "Tem caminho",
        "path_length": "Comprimento do caminho",
        "has_query": "Tem parâmetros",
        "query_length": "Comprimento dos parâmetros",
        "uses_https": "Usa HTTPS",
        "ssl_has_valid_cert": "Certificado SSL válido",
        "ssl_cert_days_to_expiry": "Dias até vencer SSL",
        "ssl_cert_days_since_start": "Dias desde início SSL",
        "country_risk": "Risco por país",
    }
    _FEATURE_LABELS_EN: Dict[str, str] = {
        "url_length": "URL Length",
        "url_entropy": "URL Entropy",
        "num_digits": "Number of Digits",
        "digits_ratio": "Digits Ratio",
        "has_at": "At (@) symbol",
        "has_dash": "Dash in domain",
        "has_question_mark": "Question Mark",
        "has_suspicious_words": "Suspicious words",
        "suspicious_words_count": "Count of suspicious words",
        "excessive_digits": "Excessive digits",
        "num_subdomains": "Number of subdomains",
        "subdomain_length": "Subdomain length",
        "domain_length": "Domain length",
        "suffix_length": "Suffix length",
        "is_ip_address": "IP as address",
        "is_shortened_url": "Shortened URL",
        "has_path": "Has path",
        "path_length": "Path length",
        "has_query": "Has query",
        "query_length": "Query length",
        "uses_https": "Uses HTTPS",
        "ssl_has_valid_cert": "Valid SSL certificate",
        "ssl_cert_days_to_expiry": "Days to SSL expiry",
        "ssl_cert_days_since_start": "Days since SSL start",
        "country_risk": "Country Risk",
    }
    
    # Decide qual dicionário de labels usar
    is_en = (lang == "English")
    labels = _FEATURE_LABELS_EN if is_en else _FEATURE_LABELS_PT

    df = pd.DataFrame(top_shap)
    df["Impact"] = df["shap_value"].apply(lambda v: "🔴 +" if v > 0 else "🟢 −")
    df["Feature"] = df["feature"].map(lambda x: labels.get(x, x))

    # Título removido a pedido do usuário: "tirar a seção 'Por que este resultado?'"
    st.dataframe(
        df[["Feature", "Impact", "shap_value"]].rename(
            columns={"shap_value": "Score"}
        ),
        use_container_width=True,
        hide_index=True,
    )
    st.markdown(f"<div style='font-size:.78rem;color:#8892a4'>{T['shap_legend']}</div>", unsafe_allow_html=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main() -> None:
    st.set_page_config(
        page_title="URL Phishing Verifier",
        page_icon="🛡️",
        layout="centered",
    )
    apply_style()

    # ── Language selection in Header ──
    if "lang" not in st.session_state:
        st.session_state["lang"] = "Português"

    c_title, c_lang = st.columns([4, 1])
    with c_title:
        pass  # Title rendered below in scan-header
    with c_lang:
        # Toggle language with flags
        if st.session_state["lang"] == "Português":
            if st.button("🇺🇸 EN", key="lang_btn"):
                st.session_state["lang"] = "English"
                st.rerun()
        else:
            if st.button("🇧🇷 PT", key="lang_btn"):
                st.session_state["lang"] = "Português"
                st.rerun()

    lang = st.session_state["lang"]
    T = TRANSLATIONS[lang]

    # ── Scan-line animated header ──
    st.markdown(f"""
    <div class="scan-header">
        <h1 style="margin:0">{T['title']}</h1>
        <div class="scan-subtitle">{T['subtitle']}</div>
    </div>
    """, unsafe_allow_html=True)

    predictor = load_predictor()
    if predictor is None:
        st.warning(
            f"⚠️ **{T['found_db']}**" if lang == "English" else "⚠️ **Modelo não encontrado.** Treine primeiro:"
        )
        st.code("python3 scripts/train_model.py --csv data/processed/dataset.csv --artifacts-dir artifacts")
        st.stop()

    # ── Parâmetros fixos (Requisito do Usuário) ──
    enable_ssl = True
    enable_geo = True
    geo_method = "dns_api"
    top_k = 12

    st.markdown("")

    # ── Input ────────────────────────────────
    url = st.text_input(
        T["input_label"],
        placeholder=T["input_placeholder"],
        key="url_input",
    )

    should_analyze = bool(url and url.strip())

    if not should_analyze:
        st.caption(f"💡 {T['input_help']}")
        st.stop()

    # ── Check database first ────────────────
    cached = lookup_url(url)
    force_recheck = False

    if cached and "force_recheck" not in st.session_state:
        st.markdown(f"<div class='source-note'>{T['found_db']}</div>", unsafe_allow_html=True)
        
        # Translate risk class for display if needed
        disp_risk: str = str(cached.risk_class) if cached.risk_class else "Suspeito"
        if lang == "English":
            risk_map = {"Seguro": "Safe", "Suspeito": "Suspicious", "Malicioso": "Malicious"}
            disp_risk = risk_map.get(disp_risk, disp_risk)

        _render_badge(disp_risk, T)
        cached_shap = cached.details.get("top_shap_features", []) if cached.details else []
        adj_score = _shap_adjusted_score(cached.score / 100.0, str(cached.risk_class), cached_shap)
        st.markdown(_confidence_html(cached.score, disp_risk, adj_score), unsafe_allow_html=True)
        st.caption(f"{T['analyzed_at']}: {cached.updated_at}")

        if cached.details:
            if "url_info" in cached.details:
                _render_dados_basicos(None, cached.details["url_info"], T)
                _render_url_details(cached.details["url_info"], T)
            if "external_results" in cached.details:
                ext_results = [
                    ExternalCheckResult(
                        source=r.get("source", ""),
                        safe=r.get("safe"),
                        details=r.get("details", ""),
                    )
                    for r in cached.details["external_results"]
                ]
                _render_external_checks(ext_results, T)
            if "top_shap_features" in cached.details:
                _render_shap(cached.details["top_shap_features"], T, lang)

    if "force_recheck" in st.session_state:
        del st.session_state["force_recheck"]

    # ── Progress bar analysis ────────────────
    progress_bar = st.progress(0, text=T["progress_starting"])

    try:
        result = predictor.predict(
            url=url,
            enable_ssl=enable_ssl,
            enable_geo=enable_geo,
            geo_method=geo_method,
            top_k_shap=top_k,
        )
        url_info = _parse_url_info(url)
    except Exception as e:
        progress_bar.empty()
        st.error(f"❌ Error: {e}")
        st.stop()

    def _progress_cb(label: str, pct: float):
        # Mini translation for progress labels if possible
        lab = label
        if lang == "English":
            if "Cloudflare" in label: lab = "Checking Cloudflare Radar..."
            if "ESET" in label: lab = "Checking ESET Link Checker..."
            if "VirusTotal" in label: lab = "Querying VirusTotal..."
            if "Google" in label: lab = "Querying Google Safe Browsing..."
        
        total = int(25 + pct * 70)
        progress_bar.progress(min(total, 95), text=lab)

    progress_bar.progress(30, text=T["progress_ai"])
    ext_data = run_all_external_checks(url, progress_callback=_progress_cb)
    meta: PageMetadata = ext_data["metadata"]
    ext_results: List[ExternalCheckResult] = ext_data["external_results"]
    
    progress_bar.progress(100, text=T["progress_done"])
    time.sleep(0.4)
    progress_bar.empty()

    # Translate result risk class
    risk_map_inv = {"Seguro": T["risk_safe"], "Suspeito": T["risk_suspicious"], "Malicioso": T["risk_malicious"]}
    disp_risk = risk_map_inv.get(result.risk_class, result.risk_class)

    # ── Save ────────────────────────────────
    details_to_save = {
        "url_info": url_info,
        "top_shap_features": result.top_shap_features,
        "external_results": [{"source": r.source, "safe": r.safe, "details": r.details} for r in ext_results],
    }
    save_result(url, result.risk_class, result.score_0_100, result.score_0_100, details_to_save)

    # ── Results ──────────────────────────────
    _render_badge(disp_risk, T)
    adj_score = _shap_adjusted_score(result.prob_phishing, result.risk_class, result.top_shap_features)
    st.markdown(_confidence_html(result.score_0_100, disp_risk, adj_score), unsafe_allow_html=True)

    if result.country_cc:
        st.caption(f"{T['detected_origin']}: **{result.country_cc}**")

    st.markdown("")
    _render_dados_basicos(meta, url_info, T)
    _render_url_details(url_info, T)
    _render_external_checks(ext_results, T)
    _render_shap(result.top_shap_features, T, lang)

    st.markdown("")
    with st.expander(T["about_title"]):
        st.write(T["about_content"])

    st.markdown("---")
    if st.button(T["btn_recheck"], type="secondary"):
        st.session_state["force_recheck"] = True
        st.rerun()


if __name__ == "__main__":
    main()
