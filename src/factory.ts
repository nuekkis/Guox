/**
 * @guox / factory.ts
 *
 * One-liner constructor for the orchestrator, with strong defaults and the
 * most common configuration surfaced at the top-level type so beginners can
 * initialize a defensible posture without reading the full schema.
 */

import { Guox } from './guox.js';
import type { GuoxOptions } from './types.js';

export function createGuox(opts: GuoxOptions): Guox {
  return new Guox(opts);
}
