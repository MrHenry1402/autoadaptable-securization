# Imagen de securization: CLI y dashboard (H6).
# Incluye nmap porque `securization profile/campaign` escanea con él. Corre sin root; los
# datos (inventario.db y securization.key) se montan en /data y nunca se copian a la imagen.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 securization \
    && mkdir /data && chown securization:securization /data
USER securization

ENV SECURIZATION_DB=/data/inventario.db \
    SECURIZATION_KEY_FILE=/data/securization.key
VOLUME ["/data"]
EXPOSE 8000

ENTRYPOINT ["securization"]
CMD ["dashboard", "--host", "0.0.0.0", "--port", "8000"]
