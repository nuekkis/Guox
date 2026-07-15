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
import type { Guox } from '../guox.js';
export interface ExpressLikeRequest {
    method: string;
    url: string;
    path?: string;
    originalUrl?: string;
    headers: Record<string, string | string[] | undefined>;
    body?: unknown;
    query?: unknown;
    params?: unknown;
    ip?: string;
    /** Buffer populated by the `express.json({ verify })` callback. */
    __guoxRawBody?: Buffer;
    /** Express' raw body Buffer installed by `express.raw()`. */
    rawBody?: Buffer;
    readonly stream?: NodeJS.ReadableStream;
}
export interface ExpressLikeResponse {
    status(code: number): this;
    header(name: string, value: string | number): this;
    json(body: unknown): void;
    end(): void;
}
export interface ExpressNext {
    (err?: unknown): void;
}
export interface ExpressAdapterOptions {
    /** Read path property to use; falls back to compute from `url`. */
    pathExtractor?: (req: ExpressLikeRequest) => string;
    /** Override raw-body location; useful for existing middleware chains. */
    rawBodyReader?: (req: ExpressLikeRequest) => Buffer | undefined;
}
export declare class ExpressAdapter {
    private readonly guox;
    private readonly opts?;
    constructor(guox: Guox, opts?: ExpressAdapterOptions | undefined);
    /** Returns an Express-compatible middleware function. */
    middleware(): (req: ExpressLikeRequest, res: ExpressLikeResponse, next: ExpressNext) => Promise<void>;
    private projectRequest;
    private projectResponse;
}
export declare function buildExpressAdapter(guox: Guox, opts?: ExpressAdapterOptions): ExpressAdapter;
//# sourceMappingURL=express.d.ts.map