FROM python:3.12-alpine@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7
COPY probe.py target.py /app/
USER 65532:65532
CMD ["python", "-B", "/app/target.py"]
