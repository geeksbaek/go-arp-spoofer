package main

import (
	"bufio"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"time"

	"net/url"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	// reMap = map[string]*regexp.Regexp{
	// "http://www.dailysecu.com/":   regexp.MustCompile(`&login_userid=(.+)&login_userpw=(.+)`),
	// "http://www.hanbit.co.kr/":    regexp.MustCompile(`&m_id=(.+)&m_passwd=(.+)`),
	// "http://www.icqa.or.kr/":      regexp.MustCompile(`&txtID=(.+)&txtPass=(.+)`),
	// "http://www.giordano.co.kr/":  regexp.MustCompile(`Data%5Bid%5D=(.+)&Data%5Bpw%5D=(.+)`),
	// "http://www.nike.co.kr/":      regexp.MustCompile(`&loginId=(.+)&password=(.+)`),
	// "http://www.junggo.com/":      regexp.MustCompile(`&mb_id=(.+)&mb_password=(.+)`),
	// "http://m.bunjang.co.kr/":     regexp.MustCompile(`userid=(.+)&userpw=(.+)`),
	// "http://www.coocha.co.kr/":    regexp.MustCompile(`mid=(.+)&mpwd=(.+)`),
	// "http://www.daisomall.co.kr/": regexp.MustCompile(`&id=(.+)&pw=(.+)`),
	// "http://www.ebsi.co.kr/":      regexp.MustCompile(`username=(.+)&j_password=(.+)`),
	// }

	reID = regexp.MustCompile(`(?i)` + `[^&]*(?:id|user|name)[^&]*=([^&]+)`)
	rePW = regexp.MustCompile(`(?i)` + `[^&]*(?:pass|pw)[^&]*=([^&]+)`)
)

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

func (h *httpStreamFactory) New(a, _ gopacket.Flow) tcpassembly.Stream {
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
				if parsed := find(body); parsed != nil {
					URL := req.Header.Get("Origin")
					if URL == "" {
						continue
					}
					ID, _ := url.QueryUnescape(parsed[0])
					PW, _ := url.QueryUnescape(parsed[1])
					wsData := struct {
						Timestamp string
						IP        string
						URL       string
						ID        string
						PW        string
					}{
						time.Now().Format("2006-01-02 15:04:05"),
						a.Src().String(),
						URL,
						ID,
						PW,
					}
					b, _ := json.Marshal(wsData)
					wsCh <- string(b)
				}
				// cookies := req.Cookies()
				// if len(cookies) > 0 {
				// 	referer := req.Header.Get("Referer")
				// 	log.Println(referer, ":", cookies)
				// }
			}
		}
	}()
	return &r
}

func find(http []byte) []string {
	// for url, re := range reMap {
	// 	parsed := re.FindSubmatch(http)
	// 	if len(parsed) != 3 {
	// 		continue
	// 	}
	// 	return []string{url, string(parsed[1]), string(parsed[2])}
	// }
	// return nil

	id := reID.FindSubmatch(http)
	pw := rePW.FindSubmatch(http)
	if len(id) == 2 && len(pw) == 2 {
		id, pw := string(id[1]), string(pw[1])
		pw = pw[:len(pw)/2] + "..."
		return []string{id, pw}
	}
	return nil
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
