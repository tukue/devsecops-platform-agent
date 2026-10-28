FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    GRADIO_ANALYTICS_ENABLED=False \
    HF_HOME=/home/advisor/.cache/huggingface \
    XDG_CACHE_HOME=/home/advisor/.cache \
    GRADIO_TEMP_DIR=/tmp/gradio

WORKDIR /app

# Install CPU-only PyTorch before resolving the application's dependencies.
COPY requirements.txt ./
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch \
    && pip install -r requirements.txt

RUN groupadd --gid 10001 advisor \
    && useradd --uid 10001 --gid 10001 --create-home --no-log-init advisor \
    && mkdir -p /home/advisor/.cache/huggingface \
    && chown -R 10001:10001 /home/advisor/.cache

# Application code remains owned by root and readable by the runtime user.
COPY app.py ./
COPY src/ ./src/
COPY data/ ./data/

USER 10001:10001
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7860/', timeout=4)"]
CMD ["python", "app.py"]
