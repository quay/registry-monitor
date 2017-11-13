# Create a build environment
FROM golang:1.9-alpine

# Install dep
RUN apk add --no-cache curl git gcc
RUN curl -o /usr/local/go/bin/dep -L https://github.com/golang/dep/releases/download/v0.3.2/dep-linux-amd64
RUN chmod +x /usr/local/go/bin/dep

# Copy the package, install its dependencies with dep, and compile it
ADD .   /go/src/github.com/coreos/registry-monitor/
WORKDIR /go/src/github.com/coreos/registry-monitor/
RUN dep ensure && CGO_ENABLED=0 go install github.com/coreos/registry-monitor

# Create a runtime environment
FROM alpine:latest
RUN apk add --no-cache dumb-init ca-certificates
COPY --from=0 /go/bin/registry-monitor .
CMD ["./registry-monitor"]
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/registry-monitor"]
