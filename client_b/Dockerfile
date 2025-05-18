FROM gcc:latest
FROM python:3.10

WORKDIR /app
COPY main.c client.py aslr.py requirements.txt ./
# RUN gcc -o main main.c
# RUN apt update && apt install -y python3 python3-pip
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

CMD ["python3", "client.py"]