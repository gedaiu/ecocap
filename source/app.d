import std.stdio;
import std.file;

import ecocap.classifier;
import ecocap.packetcapture;
import ecocap.domains;

import vibe.d;
__gshared TrafficClassifier classifier;

auto getTotals() {
	Json data = Json.emptyObject;

	data["total"] = classifier.data.serializeToJson;
	data["download"] = classifier.downloadTimeline.get.serializeToJson;
	data["upload"] = classifier.uploadTimeline.get.serializeToJson;

	return data;
}

void file(string name, string mime)(HTTPServerRequest req, HTTPServerResponse res)
{
	debug {
		string content = readText("public/" ~ name);
	} else {
		enum string content = import(name);
	}

	res.writeBody(content, mime);
}

void data(HTTPServerRequest req, HTTPServerResponse res)
{
	res.writeJsonBody(getTotals);
}

void handleWs(scope WebSocket sock)
{
	while (sock.connected) {
		try {
			auto message = sock.receiveText.parseJsonString;

			if("name" in message) {
				switch(message["name"].to!string) {
					case "report":
						sock.send(getTotals.toString);
						break;
					default:
				}
			}


		} catch(Exception e) { }
	}
}


shared static this()
{
	auto router = new URLRouter;
	router.get("/data", &data);

	router.get("/ws", handleWebSockets(&handleWs));

	router.get("/js/main.js", &file!("js/main.js", "text/javascript"));
	router.get("/js/chartist.min.js", &file!("js/chartist.min.js", "text/javascript"));
	router.get("/css/chartist.min.css", &file!("css/chartist.min.css", "text/css"));
	router.get("/", &file!("index.html", "text/html; charset=UTF-8"));

	auto settings = new HTTPServerSettings;
	settings.port = 8880;

	listenHTTP(settings, router);
}

int main()
{
	classifier = new TrafficClassifier();
	PacketCapture capture = new PacketCapture();

	capture.open();
	capture.setFilter("ip");
	capture.start();


	void packetHandler(immutable Packet packet) {
		classifier.writeln;

		if(classifier is null) {// || packet.protocol != IpProtocol.IPPROTO_TCP) {
			return;
		}

		classifier.add(packet);

		writeln("total: ", classifier.data.serializeToJson.toPrettyString);
/*
		writeln("hosts: ", classifier.hosts.serializeToJson.toPrettyString);
		writeln("remote: ", classifier.remotesData.serializeToJson.toPrettyString);
		writeln("timeline: ", classifier.downloadTimeline.get);*/
	}

	capture.handler(&packetHandler);

	scope(exit) {
		capture.close();
	}

	return runApplication();
}
