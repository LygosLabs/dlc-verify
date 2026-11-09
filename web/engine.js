// Loads dlc-verify's WebAssembly module and calls it.
//
// Every call takes a request object and answers the parsed `{ok, ...}` response (see
// docs/wasm.md). A Rust panic does not come back as an error: it traps the call with a
// `WebAssembly.RuntimeError` and leaves that instance unusable. So the module is compiled once,
// and after a trap the next call gets a fresh instance from a fresh copy of the glue (the glue
// keeps its instance in a module-level variable and will not instantiate twice).

const glue = new URL('./pkg/dlc_verify_wasm.js', import.meta.url);
const binary = new URL('./pkg/dlc_verify_wasm_bg.wasm', import.meta.url);

let compiled;
let instance;
let generation = 0;

async function compile() {
  const response = await fetch(binary);
  if (!response.ok) {
    throw new Error(`could not load ${binary.pathname}: HTTP ${response.status}`);
  }
  try {
    // Needs the server to send application/wasm; read the bytes when it does not.
    return await WebAssembly.compileStreaming(response.clone());
  } catch {
    return WebAssembly.compile(await response.arrayBuffer());
  }
}

async function instantiate() {
  compiled ??= compile().catch((error) => {
    compiled = undefined;
    throw error;
  });
  const module = await compiled;
  const dlc = await import(generation ? `${glue.href}?instance=${generation}` : glue.href);
  await dlc.default({ module_or_path: module });
  return dlc;
}

/** Loads the module, once. Rejects with why it could not. */
export function ready() {
  instance ??= instantiate().catch((error) => {
    instance = undefined;
    throw error;
  });
  return instance;
}

/** The dlc-verify version, as a string. */
export async function version() {
  return (await ready()).version();
}

/**
 * Calls `name` (`verify`, `settle`, `refund`, `profiles`, ...) with `request`, or with nothing
 * for the functions that take nothing, and answers its parsed response.
 */
export async function call(name, request) {
  const dlc = await ready();
  try {
    const answer = request === undefined ? dlc[name]() : dlc[name](JSON.stringify(request));
    return JSON.parse(answer);
  } catch (error) {
    if (!(error instanceof WebAssembly.RuntimeError)) throw error;
    generation += 1;
    instance = undefined;
    return {
      ok: false,
      error: {
        kind: 'internal',
        message: `dlc-verify crashed (${error.message}). That is a bug: please report it with the messages that caused it. The verifier has been reloaded.`,
      },
    };
  }
}
