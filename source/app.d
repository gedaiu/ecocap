import std.stdio;


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
	PacketCapture capture = new PacketCapture();

	capture.open();
	capture.setFilter("ip");
	capture.start();

	scope(exit) {
		capture.close();
	}

	return runApplication();
}
