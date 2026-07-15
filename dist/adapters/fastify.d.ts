/**
 * @guox / adapters / fastify.ts
 *
 * Fastify hook-style adapter. Designed to be attached as a `preHandler` (the
 * optimal place to install a security layer — after body parsing but before
 * the route handler runs).
 *
 * Integration pattern (see README for full snippet):
 *
 *   import Fastify from 'fastify';
 *   import { createGuox } from 'guox';
 *   import { buildFastifyAdapter } from 'guox/adapters/fastify';
 *
 *   const app = Fastify({ bodyLimit: 256 * 1024 });
 *   app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
 *     try {
 *       const raw = body as Buffer;
 *       (req as any).__guoxRawBody = raw;
 *       done(null, JSON.parse(raw.toString('utf8')));
 *     } catch (e: any) { done(e); }
 *   });
 *
 *   const guox = createGuox({ ... });
 *   app.addHook('preHandler', buildFastifyAdapter(guox).preHandlerHook());
 */
import type { Guox } from '../guox.js';
export interface FastifyLikeRequest {
    method: string;
    url: string;
    routerPath?: string;
    headers: Record<string, string | string[] | undefined>;
    body?: unknown;
    query?: unknown;
    params?: unknown;
    ip: string;
    __guoxRawBody?: Buffer;
    raw?: {
        body?: Buffer;
    };
    log?: {
        error: (msg: unknown) => void;
    };
}
export interface FastifyLikeReply {
    code(status: number): this;
    header(name: string, value: string | number): this;
    send(body: unknown): void;
}
export interface FastifyNext {
    (): void;
    (err: unknown): void;
}
export interface FastifyAdapterOptions {
    /** Where to find the parsed request path. Default `req.routerPath ?? new URL(req.url, 'http://x').pathname`. */
    pathExtractor?: (req: FastifyLikeRequest) => string;
    /** Custom raw body reader. */
    rawBodyReader?: (req: FastifyLikeRequest) => Buffer | undefined;
}
export declare class FastifyAdapter {
    private readonly guox;
    private readonly opts?;
    constructor(guox: Guox, opts?: FastifyAdapterOptions | undefined);
    /** Returns a function suitable for `app.addHook('preHandler', fn)`. */
    preHandlerHook(): (req: FastifyLikeRequest, reply: FastifyLikeReply, done: (err?: unknown) => void) => void;
    /** Promise-returning variant usable inside `addHook` with async handlers. */
    preHandlerAsync(): (req: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void>;
    private projectRequest;
    private projectResponse;
}
export declare function buildFastifyAdapter(guox: Guox, opts?: FastifyAdapterOptions): FastifyAdapter;
//# sourceMappingURL=fastify.d.ts.map