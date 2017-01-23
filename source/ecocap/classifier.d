module ecocap.classifier;

import std.string;
import std.stdio;
import std.datetime;

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

struct TrafficData {
	ulong download;
	ulong upload;

	ulong http;
	ulong https;

	void log(immutable Packet packet) {
		if(packet.isUpload) {
			upload += packet.size;
		}

		if(packet.isDownload) {
			download += packet.size;
		}

		if(packet.isHttp) {
			http += packet.size;
		}

		if(packet.isHttps) {
			https += packet.size;
		}
	}
}

class Timeline {
	ulong[] values;
	SysTime start;
	private {
		ulong size;
		ulong pass;
		ulong lastIndex;
	}

	this(ulong size) {
		this.size = size;
		values.length = size;
		this.start = Clock.currTime;
	}

	immutable(ulong[]) get() {
		return values[lastIndex+1..$].idup ~ values[0..lastIndex].idup;
	}

	void add(SysTime time, ulong value) {
		auto position = (time - start).total!"seconds";
		auto index = position % size;
		auto currentPass = position / size;

		if(currentPass != 0 && pass < currentPass - 1) {
			return;
		}

		if(currentPass > pass) {
			pass = currentPass;
			lastIndex = 0;
			values[0] = 0;
		}

		if(lastIndex < index) {
			foreach(i; lastIndex+1..index+1) {
				values[i] = 0;
			}

			lastIndex = index;
		}

		values[index] += value;
	}
}

@("set values on the right time slot")
unittest {
	auto timeline = new Timeline(3600);
	auto time = SysTime.fromISOExtString("2010-01-01T00:00:00");
	timeline.start = time;

	timeline.add(time, 1);
	assert(timeline.values[0] == 1);

	time += 1.seconds;
	timeline.add(time, 2);
	assert(timeline.values[1] == 2);

	time += 3598.seconds;
	timeline.add(time, 3);
	assert(timeline.values[3599] == 3);

	time += 1.seconds;
	timeline.add(time, 4);
	assert(timeline.values[0] == 4);

	time += 3600.seconds;
	timeline.add(time, 5);
	assert(timeline.values[0] == 5);

	time += 1.seconds;
	timeline.add(time, 6);
	assert(timeline.values[0] == 5);
	assert(timeline.values[1] == 6);

	time += 3600.seconds;
	timeline.add(time, 7);
	assert(timeline.values[0] == 0);
	assert(timeline.values[1] == 7);
}


class TrafficClassifier {
	TrafficData[string] data;
	TrafficData[string][string] remotesData;
	string[][string] hosts;
	Timeline uploadTimeline;
	Timeline downloadTimeline;

	this() {
		uploadTimeline = new Timeline(3600);
		downloadTimeline = new Timeline(3600);
	}

	void add(immutable Packet packet) {
		string key = (cast(Date) packet.date).toISOExtString();
		string remote = packet.isUpload ? packet.destinationIp : packet.sourceIp;
		hosts[remote] = remote.getHostNames;

		if(key !in data) {
			data[key] = TrafficData();
		}

		if(key !in remotesData) {
			TrafficData[string] dayTraffic;
			remotesData[key] = dayTraffic;
		}

		if(remote !in remotesData[key]) {
			remotesData[key][remote] = TrafficData();
		}

		data[key].log(packet);
		remotesData[key][remote].log(packet);

		if(packet.isUpload) {
			uploadTimeline.add(packet.date, packet.size);
		} else {
			downloadTimeline.add(packet.date, packet.size);
		}
	}
}
