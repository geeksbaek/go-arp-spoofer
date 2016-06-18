FROM ubuntu
MAINTAINER Jongyeol Baek <geeksbaek@gmail.com>

RUN apt-get update 
RUN apt-get -y install golang libpcap-dev

ENV GOPATH /go
ENV GOROOT /usr/local/go
ENV PATH /usr/local/go/bin:/go/bin:/usr/local/bin:$PATH

COPY go-arp-spoofer ./go-arp-spoofer
WORKDIR go-arp-spoofer
RUN go get -d -v
RUN go build
RUN ./go-arp-spoofer/go-arp-spoofer

EXPOSE 5000