FROM python:latest
WORKDIR /app
COPY . .
ENV API_TOKEN=abcdef1234567890xyz
RUN curl -sSL https://example.com/install.sh | bash
RUN pip install -r requirements.txt
CMD ["python", "server.py"]
