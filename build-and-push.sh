#!/usr/bin/env bash
# Build & push toutes les images Online Boutique vers Docker Hub: yosrtaktak
set -euo pipefail

DOCKERHUB_USER="yosrtaktak"
TAG="v1"   # change si tu veux versionner différemment

# Mapping service -> chemin du Dockerfile dans le repo officiel
declare -A SERVICES=(
  [paymentservice]="src/paymentservice"
  [emailservice]="src/emailservice"
  [adservice]="src/adservice"
)


# 2. Login Docker Hub
docker login -u "$DOCKERHUB_USER"

# 3. Build + tag + push pour chaque service
for svc in "${!SERVICES[@]}"; do
  path="${SERVICES[$svc]}"
  image="$DOCKERHUB_USER/$svc:$TAG"
  echo "=== Building $svc from $path -> $image ==="
  docker build -t "$image" "$path"
  echo "=== Pushing $image ==="
  docker push "$image"
done

echo "Toutes les images sont sur https://hub.docker.com/u/$DOCKERHUB_USER"

