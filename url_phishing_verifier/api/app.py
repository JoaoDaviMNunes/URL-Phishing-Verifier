from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from url_phishing_verifier.api.schemas import AnalyzeRequest, AnalyzeResponse
from url_phishing_verifier.model.predictor import URLPhishingPredictor


def create_app() -> FastAPI:
    artifacts_dir = os.environ.get("MODEL_ARTIFACTS_DIR", "artifacts")
    predictor = URLPhishingPredictor(artifacts_dir=artifacts_dir)

    app = FastAPI(title="URL-Phishing-Verifier", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/analyze", response_model=AnalyzeResponse)
    def analyze(req: AnalyzeRequest) -> Any:
        result = predictor.predict(
            url=req.url,
            enable_ssl=req.enable_ssl,
            enable_geo=req.enable_geo,
            geo_method=req.geo_method,
        )
        return {
            "url": result.url,
            "risk_class": result.risk_class,
            "score_0_100": result.score_0_100,
            "score_segment_label": result.score_segment_label,
            "prob_phishing": result.prob_phishing,
            "country_cc": result.country_cc,
            "country_method": result.country_method,
            "country_risk": result.country_risk,
            "top_shap_features": result.top_shap_features,
        }

    return app


app = create_app()

