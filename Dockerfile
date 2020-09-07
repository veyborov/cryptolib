FROM python:3.8-alpine

RUN apk update && apk add gmp-dev build-base gcc libffi-dev

COPY app /app
COPY requirements.txt /app
COPY gunicorn.conf.py /app
COPY versions.json /versions.json

RUN pip install -r /app/requirements.txt

EXPOSE 3010

CMD ["gunicorn", "app.server:app", "--bind", "0.0.0.0:3010", "-c", "/app/gunicorn.conf.py"]
