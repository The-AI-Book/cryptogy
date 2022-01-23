FROM python:3.11.0a4-slim-bullseye
LABEL key="Cryptogy"
ENV PYTHONUNBUFFERED 1
RUN apt-get update
#RUN apt-get -y install build-essential
#RUN apt-get -y install default-libmysqlclient-dev
RUN apt-get -y install nano
RUN mkdir /cryptogy
WORKDIR /cryptogy
COPY ./ /cryptogy
RUN pip install -r "./requirements.txt"