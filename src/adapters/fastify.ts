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
import type {
  AdapterRequest,
  AdapterResponse,
  Next,
} from '../types.js';

/* eslint-disable @typescript-eslint/no-explicit-any -- Fastify's request
   types are intentionally generic in @types/fastify; we model the surface we
   need and stay decoupled from version churn. */

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
  raw?: { body?: Buffer };
  log?: { error: (msg: unknown) => void };
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

export class FastifyAdapter {
  constructor(
    private readonly guox: Guox,
    private readonly opts?: FastifyAdapterOptions,
  ) {}

  /** Returns a function suitable for `app.addHook('preHandler', fn)`. */
  preHandlerHook(): (req: FastifyLikeRequest, reply: FastifyLikeReply, done: (err?: unknown) => void) => void {
    return (req, reply, done) => {
      const adapterReq = this.projectRequest(req);
      const adapterRes = this.projectResponse(reply);
      // Fastify expects either `done()` to be called or a Promise returned.
      this.guox
        .run(adapterReq, adapterRes, done as Next)
        .then((outcome) => {
          // If the orchestrator wrote a response itself, we MUST NOT call
          // `done()` — that would invoke the route handler with no payload to
          // read. Fastify's promise semantics make this safe to ignore.
          if (outcome === 'continue') {
            // already called by `next`.
          } else {
            // 'responded': clear the route handler invocation. Fastify
            // versions >=4 allow us to call done() to short-circuit.
            done();
          }
        })
        .catch((e) => {
          try {
            (req.log ?? { error: (_: unknown) => undefined }).error(e);
          } catch {
            /* ignore */
          }
          done(e);
        });
    };
  }

  /** Promise-returning variant usable inside `addHook` with async handlers. */
  preHandlerAsync(): (req: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void> {
    return async (req, reply) => {
      const adapterReq = this.projectRequest(req);
      const adapterRes = this.projectResponse(reply);
      await new Promise<void>((resolve, reject) => {
        this.guox
          .run(adapterReq, adapterRes, (err) => {
            if (err) reject(err);
            else resolve();
          })
          .then(() => resolve())
          .catch(reject);
      });
    };
  }

  private projectRequest(req: FastifyLikeRequest): AdapterRequest {
    const headers = req.headers ?? {};
    const pathStr = this.opts?.pathExtractor
      ? this.opts.pathExtractor(req)
      : req.routerPath ?? pathFromUrl(req.url);
    const rawBody =
      this.opts?.rawBodyReader?.(req) ??
      req.__guoxRawBody ??
      (req.raw?.body as Buffer | undefined);
    return {
      method: req.method,
      path: pathStr,
      url: req.url,
      headers,
      rawBody: rawBody ?? Buffer.alloc(0),
      body: req.body,
      query: req.query,
      params: req.params,
      ip: req.ip,
    };
  }

  private projectResponse(reply: FastifyLikeReply): AdapterResponse {
    return {
      setHeader: (name, value) => {
        reply.header(name, value);
      },
      setStatus: (code) => {
        reply.code(code);
      },
      sendJson: (body) => {
        reply.send(body);
      },
      end: () => {
        /* Fastify's `reply.send()` terminates the response; no explicit
           `end()` is provided. The orchestrator should not call `next()`
           after a sanitization call. Adapters communicate that by returning
           `'responded'` so the orchestrator skips `next()`. Here we just
           no-op. */
      },
    };
  }
}

export function buildFastifyAdapter(
  guox: Guox,
  opts?: FastifyAdapterOptions,
): FastifyAdapter {
  return new FastifyAdapter(guox, opts);
}

function pathFromUrl(url: string): string {
  const q = url.indexOf('?');
  if (q >= 0) return url.slice(0, q);
  const hash = url.indexOf('#');
  if (hash >= 0) return url.slice(0, hash);
  return url;
}
