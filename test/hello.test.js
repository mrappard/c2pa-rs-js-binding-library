import { expect, test } from 'vitest';
import { sayHello } from '../src/index';

test('sayHello returns greeting from Rust', () => {
  expect(sayHello()).toBe('Hello from Rust!');
});
