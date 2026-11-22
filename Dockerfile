FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure results and logs directories exist. To persist scan history across container
# restarts in local mode, mount results as a volume:
#   docker run -v $(pwd)/results:/app/results ...
RUN mkdir -p results logs

# Run as a non-privileged user — the scanner is read-only and does not require root
RUN useradd --create-home --uid 1000 scanner && chown -R scanner:scanner /app
USER scanner

EXPOSE 8501

# Lightweight health check using Python standard library (avoids needing curl in slim image)
HEALTHCHECK CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8501/_stcore/health').getcode() == 200 else 1)"

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
