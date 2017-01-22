module ecocap.classifier;

import std.string;
import std.stdio;

import ecocap.packetcapture;
import ecocap.domains;

enum IpType {
	Loopback,
	LocalNetwork,
	Internet
}

IpType ipType(string ip) {
	if(ip.indexOf("127.") == 0 || ip.indexOf("0.") == 0) {
		return IpType.Loopback;
	}

	if(ip.indexOf("10.") == 0 || ip.indexOf("172.") == 0 || ip.indexOf("192.168.") == 0) {
		return IpType.LocalNetwork;
	}

	return IpType.Internet;
}

bool isUnknown(Packet packet) {
	return packet.isUpload && packet.isDownload;
}

bool isUpload(Packet packet) {
	return packet.sourceIp.ipType == IpType.LocalNetwork && packet.destinationIp.ipType == IpType.Internet;
}

bool isDownload(Packet packet) {
	return  packet.sourceIp.ipType == IpType.Internet && packet.destinationIp.ipType == IpType.LocalNetwork;
}

bool isHttps(Packet packet) {
	return packet.sourcePort == 443 || packet.destinationPort == 443;
}

bool isHttp(Packet packet) {
	return packet.sourcePort == 80 || packet.destinationPort == 80;
}

class TrafficClassifier {
	ulong download;
	ulong upload;

	void add(immutable Packet packet) {
		if(packet.isUpload) {
			upload += packet.size;
		}

		if(packet.isDownload) {
			download += packet.size;
		}

		debug writeln("[" , packet.date , "] #",
			packet.protocol ," ",
			packet.sourceIp, ":", packet.sourcePort, packet.sourceIp.getHostNames , " -> ",
			packet.destinationIp, ":", packet.destinationPort, packet.destinationIp.getHostNames, " ",
			packet.size / 1024 , "kb");
  }
}
