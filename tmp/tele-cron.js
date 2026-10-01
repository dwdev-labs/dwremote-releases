// DW Remote 텔레메트리 Cron 이동 Worker — intake D1 → safe D1 로 옮기고 intake 를 비운다(2026-10-02). [[telemetry-collection]]
// ─────────────────────────────────────────────────────────────────────────────
// 왜: 공개 쓰기 intake 가 오염/폭주돼도 '진짜 데이터셋(safe)'은 깨끗·작게 유지. safe 는 공개 URL/Worker 없음 = 외부 접근 불가.
// 서버리스·PC 독립: Cloudflare 가 cron 일정(예: 매시)에 알아서 실행 — 관리 PC 불필요. 한 Worker 가 D1 둘 바인딩(INTAKE 읽기/삭제·SAFE 쓰기).
// 컬럼은 자동 적응(SELECT * → 같은 컬럼 INSERT, intake 의 autoincrement id 는 빼고 safe 가 새로 매김). 스키마 바뀌면 safe 도 같이 ALTER.

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(move(env).catch(() => {}));
  },
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (url.pathname === "/health") return new Response("ok");
      if (url.pathname === "/run") {                    // 수동 트리거(테스트·즉시 이동) — EXPORT_TOKEN 비밀(운영자)
        if (!auth(req, env, url)) return json({ error: "unauthorized" }, 401);
        const moved = await move(env); return json({ ok: true, moved });
      }
      // safe 읽기(운영자 분석 전용) — EXPORT_TOKEN 비밀. safe 는 공개 쓰기 없음(Cron 만 씀)·토큰으로만 읽힘.
      if (url.pathname === "/export") {
        if (!auth(req, env, url)) return json({ error: "unauthorized" }, 401);
        const limit = Math.min(10000, Math.max(1, +(url.searchParams.get("limit") || 2000)));
        const since = +(url.searchParams.get("since") || 0);
        const rs = await env.SAFE.prepare("SELECT * FROM sessions WHERE ts > ? ORDER BY ts DESC LIMIT ?").bind(since, limit).all();
        if ((url.searchParams.get("format") || "json") === "csv") return csv(rs.results || []);
        return json({ rows: rs.results || [], count: (rs.results || []).length });
      }
      if (url.pathname === "/stats") {
        if (!auth(req, env, url)) return json({ error: "unauthorized" }, 401);
        const rs = await env.SAFE.prepare(
          `SELECT app_build, encoder, COUNT(*) n, AVG(res_changes) avg_res_changes, AVG(dur_s) avg_dur,
                  AVG(fps_avg) avg_fps, AVG(rtt_p90) avg_rtt_p90, AVG(loss_pct) avg_loss
           FROM sessions GROUP BY app_build, encoder ORDER BY app_build DESC, n DESC`).all();
        return json({ groups: rs.results || [] });
      }
    } catch (e) { return json({ error: String(e) }, 500); }
    return new Response("not found", { status: 404 });
  },
};

function auth(req, env, url) {                           // 상수시간 비교 — EXPORT_TOKEN(?token= 또는 Bearer)
  const want = env.EXPORT_TOKEN || "";
  if (!want) return false;
  let got = url.searchParams.get("token") || "";
  const h = req.headers.get("authorization") || "";
  if (!got && h.startsWith("Bearer ")) got = h.slice(7);
  if (got.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= got.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}
function csv(rows) {
  if (!rows.length) return new Response("", { headers: { "content-type": "text/csv; charset=utf-8" } });
  const cols = Object.keys(rows[0]);
  const esc = (v) => { v = v == null ? "" : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  const body = [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
  return new Response(body, { headers: { "content-type": "text/csv; charset=utf-8" } });
}

async function move(env, maxRows = 2000, batch = 500) {
  let moved = 0;
  for (let i = 0; i < Math.ceil(maxRows / batch); i++) {
    const rows = ((await env.INTAKE.prepare("SELECT * FROM sessions ORDER BY id LIMIT ?").bind(batch).all()).results) || [];
    if (!rows.length) break;
    for (const row of rows) {
      const cols = Object.keys(row).filter((k) => k !== "id");   // safe 가 자체 id 매김
      const ph = cols.map(() => "?").join(",");
      await env.SAFE.prepare(`INSERT INTO sessions (${cols.join(",")}) VALUES (${ph})`).bind(...cols.map((c) => row[c])).run();
    }
    const ids = rows.map((r) => r.id);
    await env.INTAKE.prepare(`DELETE FROM sessions WHERE id IN (${ids.map(() => "?").join(",")})`).bind(...ids).run();
    moved += rows.length;
    if (rows.length < batch) break;
  }
  return moved;
}

function json(o, status = 200) { return new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8" } }); }
