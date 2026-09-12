FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# results/ konteyner icinde yaransa bele, restart-da itmemesi ucun
# real istifadede bunu volume kimi mount etmek tovsiye olunur:
#   docker run -v $(pwd)/results:/app/results ...
RUN mkdir -p results logs

# Konteyner root kimi islememelidir - skaner yalniz oxuyur, elave icaze lazim deyil
RUN useradd --create-home --uid 1000 scanner && chown -R scanner:scanner /app
USER scanner

EXPOSE 8501

# python:3.11-slim-de curl yoxdur (kohne HEALTHCHECK hemise ugursuz olurdu) -
# ona gore yoxlamani stdlib ile edirik
HEALTHCHECK CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8501/_stcore/health').getcode() == 200 else 1)"

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
