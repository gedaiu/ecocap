import std.stdio;

import ecocap.classifier;
import ecocap.packetcapture;
import ecocap.domains;

import vibe.d;

void index(HTTPServerRequest req, HTTPServerResponse res)
{
	res.writeBody("hello");
}

shared static this()
{
	auto router = new URLRouter;
	router.get("*", &index);
	auto settings = new HTTPServerSettings;
	settings.port = 8880;

	listenHTTP(settings, router);
}

int main()
{
	TrafficClassifier classifier = new TrafficClassifier();
	PacketCapture capture = new PacketCapture();

	capture.open();
	capture.setFilter("ip");
	capture.start();


	void packetHandler(immutable Packet packet) {
		if(packet.protocol != IpProtocol.IPPROTO_TCP) {
			return;
		}

		classifier.add(packet);

		writeln("total upload: ", classifier.upload);
		writeln("total download: ", classifier.download);
	}

	capture.handler(&packetHandler);

	scope(exit) {
		capture.close();
	}

	return runApplication();
}
