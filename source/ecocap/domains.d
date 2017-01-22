module ecocap.domains;

import std.conv;
import std.datetime;
import std.string;
import std.process;
import std.stdio;

string[][string] lookupCache;

string[] getHostNames(string ip) {
	if(ip in lookupCache) {
		return lookupCache[ip];
	}

	string[] list;

	list = nslookup(ip);

	if(list.length == 0) {
		list ~= ip;
	}

	lookupCache[ip] = list;

	return list;
}

string[] nslookup(string ip) {
	string[] list;
	auto pipes = pipeProcess(["nslookup", ip ], Redirect.stdout);

	if (wait(pipes.pid) != 0) {
		writeln("lookup failed!");
	}

	foreach(line; pipes.stdout.byLine) {
		auto parts = line.split("name =");

		if(parts.length == 2) {
			list ~= parts[1].to!string.strip;
		}
	}

	return list;
}
