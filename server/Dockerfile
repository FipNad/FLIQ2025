FROM python:3.10

WORKDIR /app
COPY server.py requirements.txt ./

RUN pip install --no-cache-dir --break-system-packages -r requirements.txt
CMD ["python3", "server.py"]