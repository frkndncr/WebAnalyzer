# --- Stage 1: Build Subfinder ---
FROM golang:1.21-alpine AS subfinder-builder
RUN apk add --no-cache git
WORKDIR /build
RUN git clone https://github.com/projectdiscovery/subfinder.git && \
    cd subfinder/cmd/subfinder && \
    go build -ldflags "-s -w" -o /usr/local/bin/subfinder

# --- Stage 2: Final Backend Image ---
FROM python:3.10-slim

# Install system dependencies (git, nmap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy subfinder from builder stage
COPY --from=subfinder-builder /usr/local/bin/subfinder /usr/local/bin/subfinder

WORKDIR /app

# Copy dependencies and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend files
COPY . .

# Expose FastAPI backend port
EXPOSE 8000

# Run the backend API server by default
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
