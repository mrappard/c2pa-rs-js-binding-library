import * as wasm from '../pkg';

/**
 * Calls the Rust hello_world function and returns the result.
 */
export function sayHello(): string {
  return wasm.hello_world();
}
