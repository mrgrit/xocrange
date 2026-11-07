FROM python:3.12-slim
WORKDIR /app
COPY health.py /app/health.py
USER 65532:65532
EXPOSE 8080
CMD ["python", "-B", "/app/health.py"]
