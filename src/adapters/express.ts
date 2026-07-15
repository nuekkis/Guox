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
import type {
  AdapterRequest,
  AdapterResponse,
  Next,
} from '../types.js';

/* eslint-disable @typescript-eslint/no-explicit-any -- Express' types are
   lazy/intrusive; using `any` here keeps peerDependencies optional. */

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

export class ExpressAdapter {
  constructor(
    private readonly guox: Guox,
    private readonly opts?: ExpressAdapterOptions,
  ) {}

  /** Returns an Express-compatible middleware function. */
  middleware(): (req: ExpressLikeRequest, res: ExpressLikeResponse, next: ExpressNext) => Promise<void> {
    return async (req, res, next) => {
      const adapterReq = this.projectRequest(req);
      const adapterRes = this.projectResponse(res);
      try {
        await this.guox.run(adapterReq, adapterRes, next as Next);
      } catch (e) {
        // Last-line defense — never let the security middleware take the app down.
        next(e);
      }
    };
  }

  private projectRequest(req: ExpressLikeRequest): AdapterRequest {
    const headers = req.headers ?? {};
    const pathStr = this.opts?.pathExtractor
      ? this.opts.pathExtractor(req)
      : req.path ?? stripQuery(req.url ?? req.originalUrl ?? '/');
    const rawBody =
      this.opts?.rawBodyReader?.(req) ??
      req.__guoxRawBody ??
      (req.rawBody as Buffer | undefined);
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

  private projectResponse(res: ExpressLikeResponse): AdapterResponse {
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
        } catch {
          /* swallowed */
        }
      },
    };
  }
}

export function buildExpressAdapter(
  guox: Guox,
  opts?: ExpressAdapterOptions,
): ExpressAdapter {
  return new ExpressAdapter(guox, opts);
}

function stripQuery(url: string): string {
  const q = url.indexOf('?');
  if (q >= 0) return url.slice(0, q);
  const hash = url.indexOf('#');
  if (hash >= 0) return url.slice(0, hash);
  return url;
}
