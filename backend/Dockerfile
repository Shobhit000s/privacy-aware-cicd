FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt

FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="privacy-cicd-backend" \
      org.opencontainers.image.description="Business application API deployed by the privacy-aware CI/CD pipeline"

RUN groupadd -r appuser && useradd -r -g appuser -u 1000 appuser
WORKDIR /app

COPY --from=builder /build/deps /usr/local/lib/python3.12/site-packages
COPY . .

USER 1000
ENV PYTHONUNBUFFERED=1

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]