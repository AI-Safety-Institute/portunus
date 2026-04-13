FROM python:3.12-slim
RUN pip install --no-cache-dir 'websockets>=12.0,<14'
COPY server.py /app/server.py
CMD ["python", "/app/server.py"]
