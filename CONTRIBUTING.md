# Contributing to Guox 🦊

First off, thank you for taking the time to contribute! It’s people like you that make `Guox` a robust, production-grade security layer for everyone.

By contributing to this project, you agree to abide by our standards and coding practices.

---

## Development Setup

To get started with local development, follow these steps:

1. **Fork the Repository** on GitHub.
2. **Clone your fork** locally:
   git clone https://github.com/nuekkis/Guox.git
   cd guox

3. **Install Dependencies**:
   npm install

4. **Run a Local Redis Instance** (Required for Rate Limiting & Session tests). If you have Docker installed, you can spin up Redis instantly:
   docker run -d -p 6379:6379 --name guox-redis redis:alpine

5. **Run Tests** to verify your setup:
   npm test

---

## Code Quality Standards

Since `Guox` is a **high-performance, security-critical** library, we enforce strict guidelines:

*   **TypeScript Only:** Write clean, strictly-typed TypeScript. No `any` types allowed.
*   **Performance is King:** Avoid heavy synchronous tasks that block the Node.js Event Loop. Offload data operations to Redis via optimized Lua scripts wherever possible.
*   **Zero Dependencies:** Do not introduce new external runtime dependencies unless absolutely critical and approved by maintainers.
*   **Defensive Programming:** Always write secure code. Mitigate timing attacks, sanitize inputs, handle malformed JSON, and build circuit breakers for database outages.

---

## Pull Request Guidelines

Before submitting your PR, please ensure:

1. Your code compiles with zero errors: `npm run build`.
2. Existing and new tests pass successfully: `npm test`.
3. Your commits follow the [Conventional Commits](https://www.conventionalcommits.org/) specification (e.g., `feat: add dynamic CIDR matching`, `fix: prevent potential Replay drift`).
4. You have updated the documentation or `README.md` if your changes introduce new configurations or features.

Thank you for making Node.js APIs safer! 🚀
