const path = require('path');
const ROOT = __dirname;

/** @type {import('@jest/types').Config.InitialOptions} */
module.exports = {
  testEnvironment: 'node',
  rootDir: ROOT,
  testMatch: ['<rootDir>/tests/**/*.test.ts'],
  transform: {
    '^.+\\.ts$': [
      require.resolve('ts-jest'),
      { tsconfig: path.join(ROOT, 'tsconfig.json') },
    ],
  },
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  moduleFileExtensions: ['ts', 'js', 'json'],
  collectCoverageFrom: ['src/**/*.ts'],
  coveragePathIgnorePatterns: ['/node_modules/', '/dist/', '/tests/'],
  coverageReporters: ['text', 'lcov', 'clover'],
  verbose: true,
};
