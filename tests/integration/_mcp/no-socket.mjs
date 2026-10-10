// Preloaded into the server process by `mcp-server.test.ts` (node --import).
// Every way a Node process can reach a network is made to say so on stderr and
// throw, so a session that opened a connection cannot pass quietly.
//
// A connection to a filesystem PATH is let through: the TypeScript loader
// (tsx) talks to itself over a local pipe in the temp directory. That is
// inter-process plumbing on this machine, not a network. Anything with a host
// or a port trips.
import dgram from "node:dgram";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { syncBuiltinESMExports } from "node:module";

const trip = (what) => () => {
  process.stderr.write(`SOCKET-OPENED:${what}\n`);
  throw new Error(`network access attempted: ${what}`);
};
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  const local = typeof first === "string" || (first && typeof first.path === "string");
  if (local) return connect.apply(this, args);
  return trip("net.Socket.connect")();
};
http.request = trip("http.request");
https.request = trip("https.request");
http.get = trip("http.get");
https.get = trip("https.get");
dgram.createSocket = trip("dgram.createSocket");
dns.lookup = trip("dns.lookup");
dns.promises.lookup = trip("dns.promises.lookup");
globalThis.fetch = trip("fetch");
syncBuiltinESMExports();
