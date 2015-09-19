FROM gliderlabs/alpine:3.2
MAINTAINER Charlie Lewis <defermat@defermat.net>

RUN apk-install \
        python \
        python-dev \
        build-base \
        py-pip

COPY . /app
WORKDIR /app
RUN pip install -r /app/requirements.txt

CMD ["/usr/bin/python", "main.py"]
