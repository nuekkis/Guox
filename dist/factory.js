"use strict";
/**
 * @guox / factory.ts
 *
 * One-liner constructor for the orchestrator, with strong defaults and the
 * most common configuration surfaced at the top-level type so beginners can
 * initialize a defensible posture without reading the full schema.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGuox = createGuox;
const guox_js_1 = require("./guox.js");
function createGuox(opts) {
    return new guox_js_1.Guox(opts);
}
//# sourceMappingURL=factory.js.map