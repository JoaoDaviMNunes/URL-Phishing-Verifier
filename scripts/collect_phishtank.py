from __future__ import annotations

import sys
import argparse
import os
from pathlib import Path

# Garante que o diretório raiz do projeto esteja no PYTHONPATH para encontrar 'url_phishing_verifier'
sys.path.append(str(Path(__file__).parent.parent))

from url_phishing_verifier.collection.phishtank import collect_phishtank


def main() -> None:
    parser = argparse.ArgumentParser(description="Coleta URLs maliciosas estilo PhishTank (dump/feed de texto).")
    parser.add_argument("--dump-url-or-path", required=True, help="URL HTTP ou caminho local com texto contendo URLs.")
    parser.add_argument("--out", required=True, help="CSV de saída (url,label).")
    parser.add_argument("--limit", type=int, default=None, help="Limite de URLs.")
    args = parser.parse_args()

    out_csv = collect_phishtank(
        dump_url_or_path=args.dump_url_or_path,
        out_csv_path=args.out,
        limit=args.limit,
    )
    print(f"Coleta concluida: {os.path.abspath(out_csv)}")


if __name__ == "__main__":
    main()

