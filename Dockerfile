FROM python:3.10-slim

# Install system dependencies (git, nmap, wget, ca-certificates)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    nmap \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install precompiled subfinder binary directly (v2.6.6)
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.tar.gz && \
    tar -xzvf subfinder_2.6.6_linux_amd64.tar.gz -C /usr/local/bin/ subfinder && \
    rm subfinder_2.6.6_linux_amd64.tar.gz

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
