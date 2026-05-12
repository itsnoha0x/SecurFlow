#!/bin/bash
set -e

echo "🔒 SECURFLOW CTI - Docker Scan"

if [ ! -d "/app" ]; then
    echo "❌ Erreur: volume /app non monté"
    echo "Utilisation: docker run --rm -v \$(pwd):/app securflow/scanner"
    exit 1
fi

RESULTS_DIR="/app/.securflow-results"
mkdir -p $RESULTS_DIR

export APP_PATH="/app"
export SHARED_PATH="$RESULTS_DIR"
ln -sfn $RESULTS_DIR /opt/securflow/shared

cd /opt/securflow

python src/p1_scanner/scanner.py --path "$APP_PATH" || true
python src/p2_enricher/enricher.py || true
python src/p3_decision_engine/decision_engine.py || true

cp -r src/p4_dashboard $RESULTS_DIR/

echo "✅ Scan terminé"
echo "📊 Résultats: $RESULTS_DIR/"
echo "🌐 Dashboard: $RESULTS_DIR/p4_dashboard/index.html"
