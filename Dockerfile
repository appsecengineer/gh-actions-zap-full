FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    pkg-config \
    default-libmysqlclient-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /apps/

COPY app/ /apps/

RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /apps/requirements.txt

ENV APP_HOST=0.0.0.0
ENV APP_PORT=5050
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

EXPOSE 5050

CMD ["python", "app.py"]
    