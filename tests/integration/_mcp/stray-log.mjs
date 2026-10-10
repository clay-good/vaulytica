// Preloaded into the server process by `mcp-server.test.ts`. It stands in for
// a dependency that prints: `console.log` is looked up at call time, so these
// lines go wherever the server has pointed it. If the server stopped rebinding
// console.log to stderr, they would land in the protocol stream.
//
// It starts printing when the server writes its FIRST frame, not on a timer
// from process start: a preload runs before the server's own modules load, and
// a line printed in that window is printed before any server code exists to
// redirect it. (A timer was a race — it passed on a fast machine and failed on
// CI.) From the first frame on, the server is up and every line is its to route.
const write = process.stdout.write.bind(process.stdout);
let started = false;
process.stdout.write = (...args) => {
  if (!started) {
    started = true;
    const timer = setInterval(() => {
      console.log("STRAY-LOG from a dependency");
      console.info("STRAY-INFO from a dependency");
    }, 10);
    timer.unref();
  }
  return write(...args);
};
