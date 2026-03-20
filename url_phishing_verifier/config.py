from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class GeoRiskConfig:
    """
    Heuristica simples para "feature interessante" de risco por regiao.
    Pode ser substituida por uma API/DB real em produção.
    """

    # ccTLD (inferido pelo sufixo) -> risco [0..1]
    ccTld_risk: Dict[str, float] = None

    def __post_init__(self):
        if self.ccTld_risk is None:
            object.__setattr__(
                self,
                "ccTld_risk",
                {
                    # Exemplo: lista heuristica; ajuste conforme seu dataset.
                    "ru": 0.8,
                    "cn": 0.6,
                    "kp": 0.9,
                    "ir": 0.7,
                    "pk": 0.7,
                    "ng": 0.6,
                    "br": 0.4,
                    "za": 0.5,
                    "tr": 0.5,
                    "id": 0.4,
                },
            )

    def risk_for_cc(self, cc_tld: str) -> float:
        if not cc_tld:
            return 0.2
        return float(self.ccTld_risk.get(cc_tld.lower(), 0.2))


DEFAULT_GEO_RISK = GeoRiskConfig()


SCORE_SEGMENTS: Tuple[Tuple[int, int, str], ...] = (
    (0, 20, "Seguro"),
    (20, 40, "Saudável"),
    (40, 60, "Atenção"),
    (60, 80, "Perigoso"),
    (80, 100, "Crítico"),
)


def classify_risk_from_score(score_0_100: float) -> str:
    s = max(0.0, min(100.0, float(score_0_100)))
    if s < 40.0:
        return "Seguro"
    if s < 80.0:
        return "Suspeito"
    return "Malicioso"

