FROM golang
MAINTAINER Jongyeol Baek <geeksbaek@gmail.com>

COPY go-arp-spoofer ./go-arp-spoofer
WORKDIR go-arp-spoofer
RUN go get -d -v
RUN go build
RUN sudo ./go-arp-spoofer/go-arp-spoofer

EXPOSE 5000