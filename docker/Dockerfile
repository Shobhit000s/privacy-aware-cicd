# Multi-stage build to keep the final image minimal and low-CVE-surface for Trivy
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt

FROM python:3.11-slim AS runtime

# Never bake secrets into the image; they are injected at runtime via Vault Agent / K8s secrets
LABEL org.opencontainers.image.title="privacy-aware-app" \
      org.opencontainers.image.description="Demo service deployed by the privacy-aware CI/CD pipeline"

RUN groupadd -r appuser && useradd -r -g appuser -u 1000 appuser
WORKDIR /app

COPY --from=builder /build/deps /usr/local/lib/python3.11/site-packages
COPY dashboard/ ./dashboard/
COPY ml/risk_predictor/ ./ml/risk_predictor/

# Drop privileges
USER 1000
ENV PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/healthz')" || exit 1

ENTRYPOINT ["python", "dashboard/app.py"]
