# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /build

# System packages needed for lxml, matplotlib, wordcloud, and Selenium
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ \
        libxml2-dev libxslt1-dev \
        libffi-dev \
        && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# Download spaCy model into the prefix so it's copied in stage 2
RUN python -m spacy download en_core_web_sm


# ── Stage 2: runtime image ─────────────────────────────────────────────────────
FROM python:3.13-slim

WORKDIR /app

# Runtime system libraries (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 libxslt1.1 \
        && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy project source
COPY . .

# Create data directories so the toolkit can write to them
RUN mkdir -p data/reports data/exports data/models

# Streamlit dashboard port
EXPOSE 8501

# Default: run the Streamlit dashboard.
# Override CMD to run the CLI, demo script, etc.
CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true"]
