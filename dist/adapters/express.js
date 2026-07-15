"use strict";
/**
 * @guox / adapters / express.ts
 *
 * Express middleware adapter. Projects an Express request/response onto
 * Guox's adapter-agnostic surface, captures the raw body (via the integrator's
 * `express.json({ verify })` callback or the route-level `express.raw`),
 * dispatches to `Guox.run()`, and maps the outcome to Express' `next()`.
 *
 * Integration pattern (see README for full snippet):
 *
 *   import express from 'express';
 *   import { createGuox } from 'guox';
 *   import { buildExpressAdapter } from 'guox/adapters/express';
 *
 *   const guox = createGuox({ ... });
 *   constAdapter = buildExpressAdapter(guox);
 *   app.use(express.json({ verify: (req, _res, buf) => {
 *     // stash raw body so Guox can sign it
 *     (req as any).__guoxRawBody = buf;
 *   }}));
 *   app.use(adapter.middleware());
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExpressAdapter = void 0;
exports.buildExpressAdapter = buildExpressAdapter;
class ExpressAdapter {
    guox;
    opts;
    constructor(guox, opts) {
        this.guox = guox;
        this.opts = opts;
    }
    /** Returns an Express-compatible middleware function. */
    middleware() {
        return async (req, res, next) => {
            const adapterReq = this.projectRequest(req);
            const adapterRes = this.projectResponse(res);
            try {
                await this.guox.run(adapterReq, adapterRes, next);
            }
            catch (e) {
                // Last-line defense — never let the security middleware take the app down.
                next(e);
            }
        };
    }
    projectRequest(req) {
        const headers = req.headers ?? {};
        const pathStr = this.opts?.pathExtractor
            ? this.opts.pathExtractor(req)
            : req.path ?? stripQuery(req.url ?? req.originalUrl ?? '/');
        const rawBody = this.opts?.rawBodyReader?.(req) ??
            req.__guoxRawBody ??
            req.rawBody;
        return {
            method: req.method,
            path: pathStr,
            url: req.url ?? req.originalUrl ?? pathStr,
            headers,
            rawBody: rawBody ?? Buffer.alloc(0),
            body: req.body,
            query: req.query,
            params: req.params,
            ip: req.ip,
        };
    }
    projectResponse(res) {
        return {
            setHeader: (name, value) => {
                res.header(name, value);
            },
            setStatus: (code) => {
                res.status(code);
            },
            sendJson: (body) => {
                res.json(body);
            },
            end: () => {
                // Some Express compatibility layers don't have `.end` after `.json`;
                // we attempt to call it defensively.
                try {
                    res.end();
                }
                catch {
                    /* swallowed */
                }
            },
        };
    }
}
exports.ExpressAdapter = ExpressAdapter;
function buildExpressAdapter(guox, opts) {
    return new ExpressAdapter(guox, opts);
}
function stripQuery(url) {
    const q = url.indexOf('?');
    if (q >= 0)
        return url.slice(0, q);
    const hash = url.indexOf('#');
    if (hash >= 0)
        return url.slice(0, hash);
    return url;
}
//# sourceMappingURL=express.js.map