from __future__ import annotations

import sys
import os
from pathlib import Path

# Garante que o diretório raiz do projeto esteja no PYTHONPATH para encontrar 'url_phishing_verifier'
sys.path.append(str(Path(__file__).parent.parent))

import uvicorn

if __name__ == "__main__":
    host = os.environ.get("API_HOST", "0.0.0.0")
    port = int(os.environ.get("API_PORT", "8000"))
    uvicorn.run("url_phishing_verifier.api.app:app", host=host, port=port, reload=False)

