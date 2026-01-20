// apps/auth/src/types/jest-global.d.ts
/// <reference types="jest" />
/// <reference types="jest-mock-extended" />

// Optional: make sure afterEach is recognized
declare const afterEach: (fn: () => void) => void;