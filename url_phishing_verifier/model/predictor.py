from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
import shap

from url_phishing_verifier.config import SCORE_SEGMENTS, classify_risk_from_score
from url_phishing_verifier.features.extractor import ExtractorOptions, URLFeatureExtractor


def _read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@dataclass(frozen=True)
class PredictResult:
    url: str
    score_0_100: float
    prob_phishing: float
    risk_class: str  # Seguro/Suspeito/Malicioso
    score_segment_label: str
    country_cc: Optional[str]
    country_method: Optional[str]
    country_risk: Optional[float]
    top_shap_features: List[Dict[str, Any]]


class URLPhishingPredictor:
    def __init__(self, artifacts_dir: str = "artifacts"):
        model_path = os.path.join(artifacts_dir, "model.joblib")
        meta_path = os.path.join(artifacts_dir, "metadata.json")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Não encontrei `{model_path}`. Rode o treino primeiro.")
        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Não encontrei `{meta_path}`.")

        self.model = joblib.load(model_path)
        self.metadata = _read_json(meta_path)

        # Colunas numéricas do treino.
        self.numeric_feature_names: List[str] = self.metadata.get("numeric_feature_names", [])
        if not self.numeric_feature_names:
            raise ValueError("metadata.json não contém `numeric_feature_names`.")

        self.best_threshold: float = float(self.metadata.get("best_threshold", 0.5))

        # SHAP explainer pode ser caro; inicializamos uma vez.
        self.shap_explainer = None
        try:
            self.shap_explainer = shap.TreeExplainer(self.model)
        except Exception:
            self.shap_explainer = None

    def _risk_segment(self, score: float) -> str:
        s = max(0.0, min(100.0, float(score)))
        for lo, hi, label in SCORE_SEGMENTS:
            if lo <= s < hi:
                return label
        return "Malicioso"

    def _select_numeric(self, X_df: pd.DataFrame) -> pd.DataFrame:
        for c in self.numeric_feature_names:
            if c not in X_df.columns:
                X_df[c] = np.nan
        return X_df[self.numeric_feature_names]

    def predict(
        self,
        url: str,
        enable_ssl: bool = False,
        enable_geo: bool = False,
        geo_method: str = "dns_api",
        top_k_shap: int = 8,
    ) -> PredictResult:
        extractor = URLFeatureExtractor(
            options=ExtractorOptions(enable_ssl=enable_ssl, enable_geo=enable_geo, geo_method=geo_method)
        )

        feats = extractor.transform([url])
        X = self._select_numeric(feats)

        country_cc = None
        country_method = None
        country_risk = None
        try:
            cc_val = feats["country_cc"].iloc[0]
            country_cc = str(cc_val).strip() or None
        except Exception:
            country_cc = None
        try:
            method_val = feats["country_method"].iloc[0]
            country_method = str(method_val).strip() or None
        except Exception:
            country_method = None
        try:
            country_risk_val = feats["country_risk"].iloc[0]
            country_risk = float(country_risk_val) if country_risk_val is not None else None
        except Exception:
            country_risk = None

        prob_phishing = float(self.model.predict_proba(X)[:, 1][0])
        score = float(prob_phishing * 100.0)
        # Para reduzir falso negativo na prática: usa o threshold ótimo do treino.
        if prob_phishing < self.best_threshold:
            risk_class = "Seguro"
        else:
            # Mantém 3 níveis, com "Malicioso" apenas para casos muito altos.
            risk_class = "Malicioso" if score >= 80.0 else "Suspeito"
        segment = self._risk_segment(score)

        top_shap: List[Dict[str, Any]] = []
        if self.shap_explainer is not None:
            try:
                shap_values = self.shap_explainer.shap_values(X)
                if isinstance(shap_values, list):
                    shap_arr = shap_values[1]
                else:
                    shap_arr = shap_values

                shap_vec = np.asarray(shap_arr).reshape(-1)
                order = np.argsort(-np.abs(shap_vec))
                for i in order[:top_k_shap]:
                    top_shap.append(
                        {
                            "feature": self.numeric_feature_names[i],
                            "shap_value": float(shap_vec[i]),
                            "abs_shap": float(abs(shap_vec[i])),
                        }
                    )
            except Exception:
                top_shap = []

        return PredictResult(
            url=url,
            score_0_100=score,
            prob_phishing=prob_phishing,
            risk_class=risk_class,
            score_segment_label=segment,
            country_cc=country_cc,
            country_method=country_method,
            country_risk=country_risk,
            top_shap_features=top_shap,
        )

