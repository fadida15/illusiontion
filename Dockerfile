FROM python:3.12-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir .

# Expose only the actual Illusiontion ADK application.
RUN mkdir -p /agents \
    && ln -s /app/app /agents/illusiontion

ENV PORT=8080

CMD ["sh", "-c", "adk api_server --host 0.0.0.0 --port ${PORT} /agents"]
