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

auto TH_OFF(T)(T th) {
	return (((th).th_offx2 & 0xf0) >> 4);
}


extern(C) {
	struct ether_header {
		ubyte[6] ether_dhost;
		ubyte[6] ether_shost;
		ushort ether_type;
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

	struct sniff_tcp {
		ushort th_sport;               /* source port */
		ushort th_dport;               /* destination port */
		uint th_seq;                 /* sequence number */
		uint th_ack;                 /* acknowledgement number */
		char  th_offx2;               /* data offset, rsvd */
		char  th_flags;
		ushort th_win;                 /* window */
		ushort th_sum;                 /* checksum */
		ushort th_urp;                 /* urgent pointer */
	};

	struct in_addr {
		uint s_addr;  // load with inet_aton()
	}

	char* inet_ntoa(in_addr);
	ushort ntohs(ushort);
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

	string sourceIp;
	long sourcePort;

	string destinationIp;
	long destinationPort;

	ulong size;
}

extern(C) void got_packet(ubyte* args, const (pcap_pkthdr*) header, const (ubyte*) packet)
{
	ether_header *ethernet;  /* The ethernet header [1] */
	sniff_ip *ip;              /* The IP header */
	sniff_tcp *tcp;            /* The TCP header */
	char *payload;                    /* Packet payload */

	ulong size_ip;
	ulong size_tcp;
	ulong size_payload;

	ethernet = cast(ether_header*)(packet);
	ip = cast(sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

	if (size_ip < 20) {
		debug writeln("   * Invalid IP header length: ", size_ip, " bytes");
		return;
	}

	string sourceIp = inet_ntoa(ip.ip_src).fromStringz.to!string;
	string destinationIp = inet_ntoa(ip.ip_dst).fromStringz.to!string;

	if(ip.ip_p != IpProtocol.IPPROTO_TCP) {
		return;
	}

	//writeln("from:", from);
	//writeln("to:", to);

	tcp = cast(sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	if (size_tcp < 20) {
		writeln("   * Invalid TCP header length:", size_tcp, "bytes");
		return;
	}


	auto sourcePort = ntohs(tcp.th_sport);
	auto destinationPort = ntohs(tcp.th_dport);

	//payload = cast(char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip.ip_len) - (size_ip + size_tcp);

	//writeln("   Payload: ", size_payload , "bytes");

	if(size_payload > 0) {
		//writeln(payload.fromStringz.to!string);
	}


	auto date = SysTime.fromUnixTime(header.ts.tv_sec);
	auto owner = cast(PacketCapture) args;
	auto packetData = immutable Packet(date, ip.ip_p.to!IpProtocol, sourceIp, sourcePort, destinationIp, destinationPort, size_payload);
	owner.gotPacket(packetData);


/+
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

	writeln(from, "=>", to);

	auto packetData = immutable Packet(date, ip.ip_p.to!IpProtocol, from, to, len);
	owner.gotPacket(packetData);+/
}

class PacketCapture : Thread {
	alias PacketHandler = void delegate(immutable(Packet)) @system;
	private __gshared {
		char* errorBuf;
		char* device;

		uint netp;  /* ip          */
	  uint maskp; /* subnet mask */
		bpf_program fp;
		pcap_pkthdr hdr;
		pcap_t *pcapHandler;

		PacketHandler callback;
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
		auto num_packets = -10;
		pcap_loop(pcapHandler, num_packets, &got_packet, cast(ubyte*)this);
	}

	void gotPacket(immutable Packet packet) {
		if(callback !is null) {
			callback(packet);
		}
	}

	void handler(T)(T packetHandler) {
		this.callback = packetHandler;
	}
}
