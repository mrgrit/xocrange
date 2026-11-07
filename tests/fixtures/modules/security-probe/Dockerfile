FROM python:3.12-alpine
COPY probe.py target.py /app/
USER 65532:65532
CMD ["python", "-B", "/app/target.py"]
