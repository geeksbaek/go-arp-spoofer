package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Host struct {
	IP      []byte
	MAC     []byte
	Netmask []byte
}

type Session struct {
	Sender   *Host
	Receiver *Host
}

type Sessions []*Session

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = true
	err          error
	timeout      time.Duration = time.Second
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
	// Will reuse these for each packet
	ethLayer layers.Ethernet
	arpLayer layers.ARP
	ipLayer  layers.IPv4
	tcpLayer layers.TCP
	// for fill arp header
	broadcast = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zerofill  = []byte{0, 0, 0, 0, 0, 0}

	device pcap.Interface

	sender   = &Host{}
	receiver = &Host{}
	attacker = &Host{}
	sessions = Sessions{}
)

func main() {
	device = selectDeviceFromUser()
	attacker.getLocalhostInfomation(device)

	// fmt.Printf("%#v\n", attacker)

	handle := openPcap(device)
	defer handle.Close()

	sessions.getAllSessionsInNetwork(attacker)
	// ch := make(chan *Session)
	// for _, session := range sessions {
	// 	go func(session *Session) {
	// 		fmt.Println(session.Sender.IP, "-", session.Receiver.IP)
	// 		session.Sender.getMACAddr(handle)
	// 		session.Receiver.getMACAddr(handle)
	// 		ch <- session
	// 	}(session)
	// }
	// fmt.Println("Ready")
	// for _ = range sessions {
	// 	session := <-ch
	// 	fmt.Println(session.Sender.IP, session.Sender.MAC)
	// 	fmt.Println(session.Receiver.IP, session.Receiver.MAC)
	// }
}

func openPcap(device pcap.Interface) *pcap.Handle {
	handle, err = pcap.OpenLive(device.Name, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	return handle
}

func (host *Host) getLocalhostInfomation(device pcap.Interface) {
	// get ip address
	for _, inf := range device.Addresses {
		if len(inf.IP) == 4 {
			host.IP = inf.IP
			host.Netmask = inf.Netmask
		}
	}

	// get mac address matched with ip
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
		if bytes.Equal([]byte(ip), host.IP) {
			host.MAC = []byte(inf.HardwareAddr)
		}
	}
}

// only work on C class
func (ss *Sessions) getAllSessionsInNetwork(localhost *Host) {
	prefixSize, _ := net.IPMask(localhost.Netmask).Size()
	cidr := net.IP(localhost.IP).String() + "/" + strconv.Itoa(prefixSize)
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal(err)
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
		hostInNetwork = append(hostInNetwork, ipCopy)
	}

	handle := openPcap(device)
	defer handle.Close()

	gateway := &Host{IP: hostInNetwork[1]}
	gateway.getMACAddr(handle)
	fmt.Println(gateway.String())

	hostInNetwork = hostInNetwork[2 : len(hostInNetwork)-1]
	for _, v := range hostInNetwork {
		sender := &Host{IP: v}
		sender.getMACAddr(handle)
		*ss = append(*ss, &Session{
			Sender:   sender,
			Receiver: gateway,
		})
		fmt.Println(sender.String())
		// working here
	}
}

func (host *Host) getMACAddr(handle *pcap.Handle) {
	ch := make(chan []byte)
	go recvARP(handle, host.IP, ch)
	sendARP(handle, host.IP, broadcast, attacker.IP, attacker.MAC, layers.ARPRequest)
	host.MAC = <-ch
	fmt.Println(host.MAC)
}

func (host *Host) String() string {
	return "IP:" + net.IP(host.IP).String() + " MAC:" + func(mac []byte) string {
		var buf bytes.Buffer
		for _, v := range mac {
			fmt.Fprintf(&buf, "%02x", v)
		}
		return buf.String()
	}(host.MAC)
}

func recvARP(handle *pcap.Handle, SourceProtAddress []byte, ch chan []byte) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&arpLayer,
			&ipLayer,
			&tcpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			// fmt.Println("Trouble decoding layers: ", err)
			continue
		}

		fmt.Println(foundLayerTypes)

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeEthernet {
				fmt.Println(ethLayer.EthernetType)
			}

			if layerType == layers.LayerTypeARP {
				if bytes.Equal(arpLayer.SourceProtAddress, SourceProtAddress) &&
					bytes.Equal(arpLayer.DstProtAddress, attacker.IP) {
					ch <- arpLayer.SourceHwAddress
				} else {
					fmt.Println(arpLayer.SourceProtAddress)
					fmt.Println(SourceProtAddress)
				}
				return
			}
		}
	}
	return
}

func sendARP(handle *pcap.Handle, DstProtAddress, DstHwAddress, SourceProtAddress, SourceHwAddress []byte, Operation uint16) {
	arpLayer := &layers.ARP{
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   byte(6),
		ProtAddressSize: byte(4),
		DstHwAddress: func() []byte {
			if bytes.Equal(DstHwAddress, broadcast) {
				return zerofill
			}
			return DstHwAddress
		}(),
		DstProtAddress:    DstProtAddress,
		SourceHwAddress:   SourceHwAddress,
		SourceProtAddress: SourceProtAddress,
		Operation:         Operation,
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(SourceHwAddress),
		DstMAC:       net.HardwareAddr(DstHwAddress),
		EthernetType: layers.EthernetTypeARP,
	}
	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		arpLayer,
	)
	outgoingPacket := buffer.Bytes()

	// Send our packet
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}
}

func selectDeviceFromUser() pcap.Interface {
	// Find all devices
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
