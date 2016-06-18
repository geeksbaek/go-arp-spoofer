FROM golang
MAINTAINER Jongyeol Baek <geeksbaek@gmail.com>

COPY . go-arp-spoofer
RUN go get -d -v
RUN go build
RUN sudo ./go-arp-spoofer

EXPOSE 5000