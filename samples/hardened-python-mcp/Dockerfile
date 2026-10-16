FROM python:3.12.7-slim
RUN useradd -m app
WORKDIR /app
COPY . .
USER app
CMD ["python", "-m", "server"]
