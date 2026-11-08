FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir Django==5.2.19 gunicorn==26.2.0
COPY health.py start.py settings.py wsgi.py /app/
COPY control /app/control
USER 65532:33
EXPOSE 8080
CMD ["python", "-B", "/app/start.py"]
