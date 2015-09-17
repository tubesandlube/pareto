FROM gliderlabs/alpine
MAINTAINER George Lewis <schvin@schvin.net>

# XXX port map
# XXX kill on exit or after x seconds

ENV REFRESHED_AT 2015-09-16

RUN apk --update add curl openssh
RUN ssh-keygen -A
RUN adduser -D user1 && mkdir ~user1/.ssh && touch ~user1/.ssh/authorized_keys && chmod -R g-rwx,o-rwx ~user1

ENTRYPOINT echo $USER && curl -o ~user1/.ssh/authorized_keys https://github.com/$USER.keys && /usr/sbin/sshd -d -D
