# This Dockerfile is for a Windows Container.
# It must be built on a Windows host with Docker Desktop configured for Windows containers.
FROM python:3.11-windowsservercore-1809

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collector.py .

CMD ["python", "collector.py"]
