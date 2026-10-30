// Cloudflare Worker: прокси к статистике WB с токенами из секретов.
// Секреты (Settings → Variables and Secrets, тип Secret):
//   WB_TOKEN_EF   — токен кабинета EF (категория «Статистика»)
//   WB_TOKEN_EZFR — токен кабинета EZFR
//   ACCESS_KEY    — любой пароль; его один раз вводят на странице дашборда
const ORIGINS = ["https://dimadali17.github.io"];
const TOKENS = { EF: "WB_TOKEN_EF", EZFR: "WB_TOKEN_EZFR" };

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    const cors = {
      "Access-Control-Allow-Origin": ORIGINS.includes(origin) ? origin : ORIGINS[0],
      "Access-Control-Allow-Methods": "GET,OPTIONS",
      "Access-Control-Allow-Headers": "X-Key,X-Cab",
      "Access-Control-Expose-Headers": "Retry-After",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    };
    const err = (status, msg) => new Response(JSON.stringify({ error: msg }), { status, headers: { ...cors, "Content-Type": "application/json" } });

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "GET") return err(405, "method");
    if (!env.ACCESS_KEY || req.headers.get("X-Key") !== env.ACCESS_KEY) return err(401, "bad key");

    // Только чтение статистики продавца: другие адреса WB через прокси недоступны
    const u = new URL(req.url);
    let target;
    try { target = new URL(u.pathname.slice(1) + u.search); } catch (e) { return err(400, "bad url"); }
    if (target.protocol !== "https:" || target.host !== "statistics-api.wildberries.ru" || !target.pathname.startsWith("/api/v1/supplier/")) return err(403, "forbidden path");

    const name = TOKENS[(req.headers.get("X-Cab") || "").toUpperCase()];
    const token = name && env[name];
    if (!token) return err(400, "no token for cabinet");

    let res;
    try { res = await fetch(target.toString(), { headers: { Authorization: token } }); } catch (e) { return err(502, "wb unreachable"); }
    const h = new Headers(res.headers);
    for (const k in cors) h.set(k, cors[k]);
    h.delete("content-encoding");
    return new Response(res.body, { status: res.status, headers: h });
  }
};
