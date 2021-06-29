# Create a build environment
FROM docker.io/library/golang:1.15-alpine

RUN apk add --no-cache gcc
# Copy the package and compile it
ADD .   /go/src/github.com/quay/registry-monitor/
WORKDIR /go/src/github.com/quay/registry-monitor/
RUN CGO_ENABLED=0 go install github.com/quay/registry-monitor

# Create a runtime environment
FROM docker.io/library/alpine:latest
RUN apk add --no-cache dumb-init ca-certificates
COPY --from=0 /go/bin/registry-monitor .
CMD ["./registry-monitor"]
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/registry-monitor"]
