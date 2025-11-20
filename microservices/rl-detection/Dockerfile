FROM python:3.10-slim

WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules
COPY ../shared /app/shared

# Copy application code
COPY app.py .

# Model directory will be mounted as volume
VOLUME /app/model

EXPOSE 5004

CMD ["python", "app.py"]
