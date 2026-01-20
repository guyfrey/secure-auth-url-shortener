/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/*.test.ts', '**/*.spec.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  transform: {
    '^.+\\.[tj]sx?$': ['ts-jest', {
      tsconfig: '<rootDir>/tsconfig.json',
      isolatedModules: true,  // This silences the deprecation warning
    }],
  },
  // Critical fix: transpile nanoid (and any future ESM deps)
  transformIgnorePatterns: [
    '/node_modules/(?!nanoid)/',  // ← This line lets ts-jest process nanoid
  ],
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
};