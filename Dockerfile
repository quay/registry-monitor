FROM golang

ENV PATH /usr/local/go/bin:$PATH
ENV GOPATH /gopath

WORKDIR /gopath/src/github.com/coreos/registry-monitor
RUN mkdir -p /gopath/src/github.com/coreos/registry-monitor
ADD monitor.go /gopath/src/github.com/coreos/registry-monitor/monitor.go

RUN go get -v ./...
RUN CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags '-w' monitor.go

ENTRYPOINT ["./monitor"]