"use strict";
/**
 * @guox / lua-scripts.ts
 *
 * Raw Redis Lua scripts. Each is multi-line TS string with its inputs declared
 * up top so integrators can audit. Scripts are loaded with `SCRIPT LOAD` at
 * boot and invoked with `EVALSHA` thereafter (saving bandwidth + parsing).
 *
 * Convention for all scripts:
 *   KEYS[n]  -> Redis keys the script touches (cluster-friendly)
 *   ARGV[n]  -> payload (numbers as strings, arrays joined by \n)
 *   returns  -> a Lua table encoded as an array; semantic contract documented
 *               per-script. Errors are returned as `{-1, "...", ...}` rather
 *               than raising, so callers branch on success instead of catch.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWT_BLACKLIST_LUA = exports.IP_REPUTATION_LUA = exports.NONCE_CHECK_LUA = exports.RATE_LIMIT_LUA = void 0;
exports.decodeRateLimitResult = decodeRateLimitResult;
exports.decodeNonceResult = decodeNonceResult;
exports.decodeIpReputationResult = decodeIpReputationResult;
/* ------------------------------------------------------------------ *
 * 1) COST-BASED SLIDING-WINDOW RATE LIMIT  (atomic single round-trip)
 * ------------------------------------------------------------------ *
 *
 * KEYS[1] = per-identity ZSET  (e.g. "guox:rl:60:ip:1.2.3.4")
 * ARGV[1] = member uniq id       (req id)
 * ARGV[2] = cost                 (number, e.g. "15")
 * ARGV[3] = window seconds       (e.g. "60")
 * ARGV[4] = max credits          (e.g. "100")
 * ARGV[5] = now                  (epoch seconds, integer)
 * ARGV[6] = ttl seconds          (window + slack, for the ZSET itself)
 * ARGV[7] = adaptive tighten     (1..100, percent of credits to allow.
 *                                  "100" = no tightening)
 *
 * Behaviour:
 *   1. ZREMRANGEBYSCORE to drop expired members.
 *   2. Sum costs of surviving members (cost encoded as suffix in each member:
 *      member = "<reqId>#<cost>").
 *   3. If (used + cost) <= effective_credits -> ZADD member with score=now,
 *      expire the key, return {1, remaining, retry_after=0, charged=cost}.
 *   4. Else: do NOT ZADD, return {0, remaining, retry_after, charged=0}.
 *
 * Notes:
 *   - The ZADD uses NX semantics AFTER the sum, so concurrent writers cannot
 *     double-charge a single reqId (collision survival).
 *   - We deliberately split "<reqId>#<cost>" so the sum loop never has to
 *     decode anything but the cost suffix.
 *   - The TTL refresh keeps the ZSET from lingering after traffic ceases.
 * ------------------------------------------------------------------ */
exports.RATE_LIMIT_LUA = `
-- Cost-based sliding-window rate limiter.
-- Inputs (see comment block above).
local key       = KEYS[1]
local reqId     = ARGV[1]
local cost      = tonumber(ARGV[2])
local windowSec = tonumber(ARGV[3])
local maxCredits = tonumber(ARGV[4])
local now       = tonumber(ARGV[5])
local ttlSec    = tonumber(ARGV[6])
local tightenPct = tonumber(ARGV[7])
if tightenPct == nil or tightenPct < 1 or tightenPct > 100 then
    tightenPct = 100
end
local effectiveCredits = math.floor(maxCredits * tightenPct / 100)
if effectiveCredits < 1 then effectiveCredits = 1 end

-- (1) drop expired members
local cutoff = now - windowSec
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)

-- (2) sum surviving costs (member = "<reqId>#<cost>")
local members = redis.call('ZRANGE', key, 0, -1)
local used = 0
for _, m in ipairs(members) do
    local sep = string.find(m, '#', 1, true)
    if sep ~= nil then
        local cStr = string.sub(m, sep + 1)
        local c = tonumber(cStr)
        if c ~= nil then
            used = used + c
        end
    end
end

-- (3) attempt admission
local charged = 0
local allowed = 0
local remaining = 0
local retryAfter = 0

if (used + cost) <= effectiveCredits then
    local member = reqId .. '#' .. tostring(cost)
    local added = redis.call('ZADD', key, 'NX', now, member)
    if added == 1 then
        allowed = 1
        charged = cost
        remaining = effectiveCredits - (used + cost)
        redis.call('EXPIRE', key, ttlSec)
    else
        -- collision: identical reqId already admitted (shouldn't happen with
        -- random reqIds, but never fail-closed on a collision).
        allowed = 1
        charged = 0
        remaining = effectiveCredits - used
    end
else
    allowed = 0
    charged = 0
    remaining = math.max(0, effectiveCredits - used)

    -- compute retry-after: smallest score whose cost can be safely dropped so
    -- the request would fit. We scan surviving members oldest-first, debut
    -- their costs until enough credit frees up; the time of the last evicted
    -- member minus now is the minimal wait.
    local need = (used + cost) - effectiveCredits
    local freed = 0
    local worstWait = windowSec - (now - cutoff)
    for _, m in ipairs(members) do
        local sep = string.find(m, '#', 1, true)
        if sep ~= nil then
            local cStr = string.sub(m, sep + 1)
            local c = tonumber(cStr)
            if c ~= nil then
                local score = tonumber(redis.call('ZSCORE', key, m))
                if score ~= nil and (now - score) < windowSec then
                    local wait = windowSec - (now - score)
                    freed = freed + c
                    if wait > worstWait then worstWait = wait end
                    if freed >= need then break end
                end
            end
        end
    end
    -- clamp to >=1 second so clients don't busy-loop on rounding
    retryAfter = math.max(1, math.ceil(worstWait))
end

return {allowed, remaining, retryAfter, charged, effectiveCredits}
`;
/* ------------------------------------------------------------------ *
 * 2) NONCE DE-DUP  (atomic SETNX + PEXPIRE)
 * ------------------------------------------------------------------ *
 *
 * KEYS[1] = "guox:nonce:<sha256(nonce)>"
 * ARGV[1] = ttl milliseconds      (only set if insert succeeds)
 * ARGV[2] = sentinel value         (any non-empty string, e.g. "1")
 *
 * Returns:
 *   {1}  -> nonce stored (first sight, request is fresh)
 *   {0}  -> nonce already exists (REPLAY)
 * ------------------------------------------------------------------ */
exports.NONCE_CHECK_LUA = `
local key = KEYS[1]
local ttlMs = ARGV[1]
local value = ARGV[2]
local inserted = redis.call('SET', key, value, 'NX', 'PX', ttlMs)
if inserted then
    return {1}
end
return {0}
`;
/* ------------------------------------------------------------------ *
 * 3) IP REPUTATION — increment violations, escalate to block if needed
 * ------------------------------------------------------------------ *
 *
 * KEYS[1] = "guox:iprep:viol:<ip>"            (violation counter)
 * KEYS[2] = "guox:iprep:block:<ip>"           (block sentinel)
 * ARGV[1] = violation threshold               ("3")
 * ARGV[2] = violation window seconds          ("300")
 * ARGV[3] = block TTL seconds                 ("600")
 * ARGV[4] = now (epoch seconds)
 *
 * Returns:
 *   {blockedNow (0|1), violations, blockTtlSeconds}
 * ------------------------------------------------------------------ */
exports.IP_REPUTATION_LUA = `
local counterKey = KEYS[1]
local blockKey   = KEYS[2]
local threshold  = tonumber(ARGV[1])
local windowSec  = tonumber(ARGV[2])
local blockTtl   = tonumber(ARGV[3])
local now        = tonumber(ARGV[4])

-- Reset counter if it expired and elapsed since first violation.
-- We chain two keys: counter value + first-at epoch to know window origin.
redis.call('EXPIRE', counterKey, windowSec)
local violations = redis.call('INCR', counterKey)
if violations == 1 then
    -- first violation in this window: ensure TTL starts now.
    redis.call('EXPIRE', counterKey, windowSec)
end

local blockedNow = 0
if violations >= threshold then
    -- (re)establish block, refresh TTL so repeated abuse keeps the ban warm.
    redis.call('SET', blockKey, '1', 'EX', blockTtl)
    blockedNow = 1
end

return {blockedNow, violations, blockTtl}
`;
/* ------------------------------------------------------------------ *
 * 4) SESSION REVOKE / BLACKLIST
 * ------------------------------------------------------------------ *
 *
 * KEYS[1] = "guox:revoked:jwt:<jti>"
 * ARGV[1] = ttl seconds (until the JWT would have naturally expired)
 * ARGV[2] = value ("1")
 *
 * Returns: {1} on success, {0} if already blacklisted (idempotent).
 * ------------------------------------------------------------------ */
exports.JWT_BLACKLIST_LUA = `
local key = KEYS[1]
local ttl = tonumber(ARGV[1])
local value = ARGV[2]
local prev = redis.call('SET', key, value, 'NX', 'EX', ttl)
if prev then return {1} end
return {0}
`;
/* ------------------------------------------------------------------ *
 * Decoders — typed conversion of EVALSHA return arrays
 * ------------------------------------------------------------------ */
/** Pull `["0","12","3","0","100"]` style array into a typed `RateLimitDecision`. */
function decodeRateLimitResult(raw) {
    // ioredis returns table elements as strings by default.
    const arr = Array.isArray(raw) ? raw.map((n) => Number(n)) : [];
    const allowed = arr[0] === 1;
    const remaining = Number.isFinite(arr[1]) ? arr[1] : 0;
    const retryAfter = Number.isFinite(arr[2]) ? arr[2] : 0;
    const charged = Number.isFinite(arr[3]) ? arr[3] : 0;
    const limit = Number.isFinite(arr[4]) ? arr[4] : 0;
    return { allowed, limit, remaining, retryAfter, charged };
}
function decodeNonceResult(raw) {
    if (Array.isArray(raw)) {
        return Number(raw[0] ?? 0) === 1;
    }
    return false;
}
function decodeIpReputationResult(raw) {
    if (!Array.isArray(raw))
        return { blockedNow: false, violations: 0 };
    return {
        blockedNow: Number(raw[0] ?? 0) === 1,
        violations: Number(raw[1] ?? 0),
    };
}
//# sourceMappingURL=lua-scripts.js.map