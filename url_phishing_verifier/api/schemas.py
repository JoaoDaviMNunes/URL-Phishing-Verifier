from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="URL para análise (http(s):// ou apenas domínio/caminho).")
    enable_ssl: bool = False
    enable_geo: bool = False
    geo_method: str = "dns_api"


class TopShapFeature(BaseModel):
    feature: str
    shap_value: float
    abs_shap: float


class AnalyzeResponse(BaseModel):
    url: str
    risk_class: str
    score_0_100: float
    score_segment_label: str
    prob_phishing: float
    country_cc: Optional[str] = None
    country_method: Optional[str] = None
    country_risk: Optional[float] = None
    top_shap_features: List[TopShapFeature]

