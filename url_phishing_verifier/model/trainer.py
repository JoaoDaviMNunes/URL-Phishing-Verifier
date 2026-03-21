from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import shap
import lightgbm as lgb
from lightgbm import LGBMClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from url_phishing_verifier.features.extractor import ExtractorOptions, URLFeatureExtractor


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _select_numeric_features(df: pd.DataFrame, numeric_feature_names: List[str]) -> pd.DataFrame:
    # LightGBM lida com NaN; mas precisa que as colunas existam.
    for c in numeric_feature_names:
        if c not in df.columns:
            df[c] = np.nan
    return df[numeric_feature_names]


@dataclass(frozen=True)
class TrainingArtifacts:
    model_path: str
    metadata_path: str


def _choose_threshold_fbeta(
    y_true: np.ndarray, proba_pos: np.ndarray, beta: float = 2.0
) -> Tuple[float, Dict[str, float]]:
    best_t = 0.5
    best_f = -1.0
    best_stats: Dict[str, float] = {}

    # Evita thresholds absurdos; o modelo geralmente tem distribuiçao concentrada.
    thresholds = np.linspace(0.01, 0.99, 99)
    for t in thresholds:
        y_pred = (proba_pos >= t).astype(int)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        # fbeta: beta>1 aumenta recall.
        if prec == 0 and rec == 0:
            f = 0.0
        else:
            f = (1 + beta * beta) * prec * rec / max(1e-12, (beta * beta * prec + rec))
        if f > best_f:
            best_f = f
            best_t = float(t)
            best_stats = {"threshold": float(t), "precision": float(prec), "recall": float(rec), "fbeta": float(f)}

    return best_t, best_stats


def _compute_shap_top_features(
    model: LGBMClassifier, X: pd.DataFrame, feature_names: List[str], top_k: int = 20, seed: int = 42
) -> Dict[str, Any]:
    # SHAP TreeExplainer é a opção mais direta para LightGBM.
    # Fazemos amostragem para reduzir custo.
    rng = np.random.default_rng(seed)
    if len(X) > 500:
        idx = rng.choice(len(X), size=500, replace=False)
        X_bg = X.iloc[idx]
    else:
        X_bg = X

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_bg)
    if isinstance(shap_values, list):
        # Para binario, shap_values costuma ser lista (classe 0 e 1).
        shap_arr = shap_values[1]
    else:
        shap_arr = shap_values

    mean_abs = np.abs(shap_arr).mean(axis=0)
    order = np.argsort(-mean_abs)
    top = []
    for i in order[:top_k]:
        top.append({"feature": feature_names[i], "mean_abs_shap": float(mean_abs[i])})
    return {"top_features": top, "num_background_samples": int(len(X_bg))}


def train_model(
    df: pd.DataFrame,
    url_column: str = "url",
    label_column: str = "label",
    artifacts_dir: str = "artifacts",
    extractor_options: Optional[ExtractorOptions] = None,
    test_size: float = 0.2,
    random_state: int = 42,
    beta_fbeta: float = 2.0,
) -> TrainingArtifacts:
    """
    Treina um modelo binario (phishing=1, seguro=0).
    Depois a classificação em 3 níveis é feita via score (0..100) no predictor.
    """

    _ensure_dir(artifacts_dir)

    extractor = URLFeatureExtractor(options=extractor_options or ExtractorOptions())
    numeric_feature_names = extractor.numeric_feature_names()

    # Prepara dataset
    if url_column not in df.columns or label_column not in df.columns:
        raise ValueError(f"Esperado colunas `{url_column}` e `{label_column}` em df.")

    urls = df[url_column].astype(str).tolist()
    y = df[label_column].astype(int).values

    feats_df = extractor.transform(urls)
    X = _select_numeric_features(feats_df, numeric_feature_names)

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )
    # Temp divide em valid/test para achar threshold.
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=random_state
    )

    pos_rate = float(y_train.mean()) if len(y_train) else 0.0
    # class_weight=balanced reduz viés e ajuda recall.
    # scale_pos_weight é opcional; aqui deixamos balance_class_weight fazer parte do ajuste.
    model = LGBMClassifier(
        objective="binary",
        n_estimators=800,
        learning_rate=0.05,
        num_leaves=63,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=0.1,
        class_weight="balanced",
        random_state=random_state,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        eval_metric="auc",
        callbacks=[lgb.log_evaluation(period=-1)],
    )

    proba_val = model.predict_proba(X_val)[:, 1]
    best_threshold, thr_stats = _choose_threshold_fbeta(y_val, proba_val, beta=beta_fbeta)

    proba_test = model.predict_proba(X_test)[:, 1]
    y_pred_test = (proba_test >= best_threshold).astype(int)

    metrics: Dict[str, Any] = {}
    metrics["accuracy"] = float(accuracy_score(y_test, y_pred_test))
    metrics["roc_auc"] = float(roc_auc_score(y_test, proba_test)) if len(np.unique(y_test)) > 1 else np.nan
    metrics["precision"] = float(precision_score(y_test, y_pred_test, zero_division=0))
    metrics["recall"] = float(recall_score(y_test, y_pred_test, zero_division=0))
    metrics["f1"] = float(f1_score(y_test, y_pred_test, zero_division=0))
    prfs = precision_recall_fscore_support(y_test, y_pred_test, zero_division=0)
    # prfs: precision per class in order [0,1] e recall per class...
    metrics["precision_per_class"] = {"0": float(prfs[0][0]), "1": float(prfs[0][1])}
    metrics["recall_per_class"] = {"0": float(prfs[1][0]), "1": float(prfs[1][1])}

    # Explicabilidade global (SHAP)
    shap_top = _compute_shap_top_features(
        model=model,
        X=X_train,
        feature_names=numeric_feature_names,
        top_k=20,
        seed=random_state,
    )

    # Feature importance do LightGBM (global)
    try:
        importances = model.feature_importances_
        imp_order = np.argsort(-importances)
        top_importances = []
        for i in imp_order[:20]:
            top_importances.append(
                {
                    "feature": numeric_feature_names[i],
                    "importance": float(importances[i]),
                }
            )
    except Exception:
        top_importances = []

    model_path = os.path.join(artifacts_dir, "model.joblib")
    meta_path = os.path.join(artifacts_dir, "metadata.json")
    joblib.dump(model, model_path)

    metadata = {
        "url_column": url_column,
        "label_column": label_column,
        "numeric_feature_names": numeric_feature_names,
        "feature_names_total": extractor.feature_names,
        "best_threshold": float(best_threshold),
        "threshold_search": {"beta_fbeta": float(beta_fbeta), **thr_stats},
        "metrics": metrics,
        "model_params": {
            "n_estimators": 800,
            "learning_rate": 0.05,
            "num_leaves": 63,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "class_weight": "balanced",
            "objective": "binary",
        },
        "shap": shap_top,
        "lightgbm_feature_importance": {"top_features": top_importances},
        "training_stats": {"train_pos_rate": pos_rate, "num_rows": int(len(df))},
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    # Feedback rápido no terminal
    print("=== Avaliação (teste) ===")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    print(f"Melhor threshold (beta={beta_fbeta}): {best_threshold:.4f}")

    return TrainingArtifacts(model_path=model_path, metadata_path=meta_path)

