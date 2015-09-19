FROM alpine

ENV REFRESHED_AT 2015-09-18

RUN apk -U add go git

RUN adduser -s sh -D go go

USER go 
WORKDIR /home/go

RUN mkdir /home/go/gocode

ENV GOPATH /home/go/gocode

RUN go get golang.org/x/crypto/pbkdf2

ADD src src

ENTRYPOINT sh

