module ecocap.packetcapture;


import std.datetime;
import std.exception;
import std.string;
import std.conv;
import std.utf;
import std.stdio;

import core.thread;
import libpcap;

pragma(lib, "lpcap");

enum SIZE_ETHERNET = 14;

auto IP_HL(T)(T ip) {
	return (((ip).ip_vhl) & 0x0f);
}


extern(C) {
	struct ether_header {
		ubyte[6]	ether_dhost;
		ubyte[6]	ether_shost;
		ushort	ether_type;
	}

	struct sniff_ip {
		ubyte ip_vhl;		/* version << 4 | header length >> 2 */
		ubyte ip_tos;		/* type of service */
		ushort ip_len;		/* total length */
		ushort ip_id;		/* identification */
		ushort ip_off;		/* fragment offset field */
		ubyte ip_ttl;		/* time to live */
		ubyte ip_p;		/* protocol */
		ushort ip_sum;		/* checksum */
		in_addr ip_src;
		in_addr ip_dst; /* source and dest address */
	}

	struct in_addr {
		ulong s_addr;  // load with inet_aton()
	}

	char* inet_ntoa(in_addr);
}

enum IpProtocol {
	IPPROTO_IP = 0,               /* Dummy protocol for TCP               */
	IPPROTO_ICMP = 1,             /* Internet Control Message Protocol    */
	IPPROTO_IGMP = 2,             /* Internet Group Management Protocol   */
	IPPROTO_IPIP = 4,             /* IPIP tunnels (older KA9Q tunnels use 94) */
	IPPROTO_TCP = 6,              /* Transmission Control Protocol        */
	IPPROTO_EGP = 8,              /* Exterior Gateway Protocol            */
	IPPROTO_PUP = 12,             /* PUP protocol                         */
	IPPROTO_UDP = 17,             /* User Datagram Protocol               */
	IPPROTO_IDP = 22,             /* XNS IDP protocol                     */
	IPPROTO_TP = 29,              /* SO Transport Protocol Class 4        */
	IPPROTO_DCCP = 33,            /* Datagram Congestion Control Protocol */
	IPPROTO_IPV6 = 41,            /* IPv6-in-IPv4 tunnelling              */
	IPPROTO_RSVP = 46,            /* RSVP Protocol                        */
	IPPROTO_GRE = 47,             /* Cisco GRE tunnels (rfc 1701,1702)    */
	IPPROTO_ESP = 50,             /* Encapsulation Security Payload protocol */
	IPPROTO_AH = 51,              /* Authentication Header protocol       */
	IPPROTO_MTP = 92,             /* Multicast Transport Protocol         */
	IPPROTO_BEETPH = 94,          /* IP option pseudo header for BEET     */
	IPPROTO_ENCAP = 98,           /* Encapsulation Header                 */
	IPPROTO_PIM = 103,            /* Protocol Independent Multicast       */
	IPPROTO_COMP = 108,           /* Compression Header Protocol          */
	IPPROTO_SCTP = 132,           /* Stream Control Transport Protocol    */
	IPPROTO_UDPLITE = 136,        /* UDP-Lite (RFC 3828)                  */
	IPPROTO_MPLS = 137,           /* MPLS in IP (RFC 4023)                */
	IPPROTO_RAW = 255             /* Raw IP packets                       */
}

struct Packet {
	SysTime date;
	IpProtocol protocol;
	string from;
	string to;
	ulong size;
}

extern(C) void got_packet(ubyte* args, const (pcap_pkthdr*) header, const (ubyte*) packet)
{
  writeln("got_packet");
	auto owner = cast(PacketCapture) args;
	auto ethernet = cast(ether_header*)(packet);

	ulong len = header.caplen;
	auto date = SysTime.fromUnixTime(header.ts.tv_sec);

	/* define/compute ip header offset */
	auto ip = cast(sniff_ip*)(packet + SIZE_ETHERNET);
	auto size_ip = IP_HL(ip)*4;
	enforce(size_ip >= 20, "Invalid IP header length: " ~ size_ip.to!string ~" bytes");

	string from = inet_ntoa(ip.ip_src).fromStringz.to!string;
	string to = inet_ntoa(ip.ip_dst).fromStringz.to!string;

	auto packetData = immutable Packet(date, ip.ip_p.to!IpProtocol, from, to, len);
	owner.gotPacket(packetData);
}

class PacketCapture : Thread {
	private {
		char* errorBuf;
		char* device;

		uint netp;  /* ip          */
	  uint maskp; /* subnet mask */
		bpf_program fp;
		pcap_pkthdr hdr;
		pcap_t *pcapHandler;
	}

	this() {
		/* ask pcap to find a valid device for use to sniff on */
		char* device = pcap_lookupdev(errorBuf);
		enforce(device !is null, errorBuf.to!string);

		/* print out device name */
		writeln("selected interface: ", device.to!string);

		this(device);
	}

	this(string monitorDevice) {
		this(monitorDevice.toUTFz!(char*));
	}

	this(char* monitorDevice) {
		/* ask pcap for the network address and mask of the device */
		auto ret = pcap_lookupnet(monitorDevice, &netp, &maskp, errorBuf);
		enforce(ret != -1, errorBuf.to!string);

		this.device = monitorDevice;
		super(&run);
	}

	~this() {
		close();
	}

	void open() {
		pcapHandler = pcap_open_live(device, BUFSIZ, 0, 0, errorBuf);
		enforce(pcapHandler !is null, errorBuf.to!string);
	}

	void close() {
		"close pcap loop".writeln;
		if(pcapHandler is null) {
			return;
		}

		pcap_breakloop(pcapHandler);
		pcap_close(pcapHandler);
		pcapHandler = null;
	}

	void setFilter(string filter) {
		/* compile the filter expression */
		auto ret = pcap_compile(pcapHandler, &fp, filter.toStringz, 0, netp);
		enforce(ret != -1, "Couldn't parse filter " ~ filter ~ " " ~ pcap_geterr(pcapHandler).fromStringz);

		/* apply the compiled filter */
		ret = pcap_setfilter(pcapHandler, &fp);
		enforce(ret != -1, "Couldn't install filter " ~ filter ~ " " ~ pcap_geterr(pcapHandler).fromStringz);
	}

	void run() {
		auto num_packets = 10;
		pcap_loop(pcapHandler, num_packets, &got_packet, cast(ubyte*)this);
	}

	void gotPacket(immutable Packet packet) {

		/* print source and destination IP addresses */
		writeln("[" , packet.date , "] #",
			packet.protocol ," ",
			packet.from , " -> ",
			packet.to, " ",
			packet.size / 1024 , "kb");
	}
}
