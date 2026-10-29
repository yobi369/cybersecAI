FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000 CYBERSECAI_DATABASE=/var/lib/cybersecai/cybersecai.db
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 --create-home appuser && mkdir -p /var/lib/cybersecai && chown -R appuser:appuser /var/lib/cybersecai /app
COPY --chown=appuser:appuser . .
USER appuser
EXPOSE 8000
CMD ["sh","-c","gunicorn --workers 2 --bind 0.0.0.0:$PORT --access-logfile - --error-logfile - app:app"]
