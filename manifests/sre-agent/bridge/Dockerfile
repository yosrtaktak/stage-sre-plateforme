# =============================================================================
#  Image du bridge SRE — remplace le duo « python:3.11-slim + ConfigMap ».
#  UNE image pour les deux Deployments : holmes-bridge (CMD par défaut) et
#  slack-gateway (command surchargée dans le manifest).
#  Base 3.11-slim = celle qui tourne déjà sur la VM → couches déjà en cache,
#  seule la couche code (quelques dizaines de Ko) se télécharge à chaque tag
#  (contrainte réseau VM ~265 Ko/s mesurée le 13/08).
#  Le code est 100 % stdlib : AUCUN pip install — pas de couche de deps à
#  maintenir, la surface CVE se réduit à l'image de base (bumpée par Renovate).
#  Destination : manifests/sre-agent/bridge/Dockerfile
#  Build CI    : .github/workflows/build-images.yml (trivy image + SBOM + cosign)
# =============================================================================
FROM python:3.11-slim

# Processus non-root dédié : la policy no-runAsRoot de l'admission StackRox
# passera sans exception, et readOnlyRootFilesystem devient possible côté
# podspec (l'état vit déjà sur le PVC /state).
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY src/ ./src/

USER 10001
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000

# holmes-bridge par défaut ; le Deployment slack-gateway surcharge avec :
#   command: ["python", "/app/src/slack-gateway.py"]
CMD ["python", "/app/src/holmes-bridge.py"]
