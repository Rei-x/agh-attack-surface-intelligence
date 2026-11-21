FROM python:3.12-alpine

RUN apk add --no-cache openssl

WORKDIR /lab
COPY *.py /lab/

ENV PYTHONUNBUFFERED=1
