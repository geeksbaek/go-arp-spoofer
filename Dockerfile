FROM ubuntu
MAINTAINER Jongyeol Baek <geeksbaek@gmail.com>

RUN apt-get update 
RUN apt-get -y install golang
RUN apt-get -y install libpcap-dev
RUN apt-get -y install git

RUN mkdir /go
ENV GOPATH /go

COPY go-arp-spoofer ./go-arp-spoofer
WORKDIR go-arp-spoofer
RUN go get -d -v
RUN go build
RUN ./go-arp-spoofer/go-arp-spoofer

EXPOSE 5000