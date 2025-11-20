FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules
COPY ../shared /app/shared

# Copy application code
COPY app.py .

# Run as non-root user (optional, may need root for packet capture)
# USER nobody

EXPOSE 5001

CMD ["python", "app.py"]
