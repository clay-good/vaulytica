// Preloaded into the server process by `mcp-server.test.ts`. It stands in for
// a dependency that prints: `console.log` is looked up at call time, so these
// lines go wherever the server has pointed it. If the server stopped rebinding
// console.log to stderr, they would land in the protocol stream.
const timer = setInterval(() => {
  console.log("STRAY-LOG from a dependency");
  console.info("STRAY-INFO from a dependency");
}, 25);
timer.unref();
