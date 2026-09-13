FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY app.py .
RUN useradd --system --uid 10003 --no-create-home mock
USER mock
EXPOSE 8900
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8900/health')"
CMD ["python", "app.py"]
