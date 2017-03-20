FROM alpine:3.5

ENV UNDER_DOCKER true

COPY bin/monitor /usr/local/bin
ENTRYPOINT ["monitor"]
