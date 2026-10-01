// DW Remote 성능 텔레메트리 수집 Worker (Cloudflare Workers + D1)
// ─────────────────────────────────────────────────────────────────────────────
// 역할: 배포본(동의 켠 서버)이 보내는 "숫자만" 세션 요약을 POST /collect 로 받아 D1(SQLite)에 쌓는다.
//  읽기(분석)는 GET /export 로, EXPORT_TOKEN 비밀로 보호 — 이 토큰은 "운영자 분석 PC + Worker 비밀"에만 있고
//  배포되는 exe 엔 절대 안 들어간다(그래서 받은 사람이 데이터를 지우거나 남의 걸 읽지 못함).
//
// 설계 근거:
//  - 쓰기는 익명 공개 끝점이다(토큰을 exe 에 넣으면 추출당해 저장소 훼손 → GitHub 직접 업로드를 피한 이유와 동일).
//    익명이라 남용(가짜 데이터·폭주)이 가능하므로: ① 본문 크기 상한 ② 엄격한 화이트리스트 검증(숫자/짧은 열거값만)
//    ③ 앱 태그(비밀 아님 — 무작위 소음만 거름) ④ Cloudflare 대시보드 Rate Limiting 규칙(README 참고)로 막는다.
//  - 저장은 숫자·짧은 열거값뿐. 화면·IP·PC 이름·비번·접속 코드·파일명·클립보드는 애초에 안 받는다(sanitize 가 버림).
//  - raw 컬럼엔 정제된 객체 전체를 JSON 으로(앞으로 컬럼에 없는 새 숫자 필드가 와도 보존). 여전히 숫자만.
//
// 배포: README.md 참고(wrangler login→d1 create→schema.sql→secret put EXPORT_TOKEN→deploy).

const MAX_BODY = 8192;          // 본문 8KB 초과 거부(숫자 요약은 ~1KB) — 메모리/저장 폭주 방지
const APP_TAG = "dwremote1";    // 비밀 아님. 엉뚱한 POST(봇·스캐너) 걸러내는 정도

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (req.method === "POST" && url.pathname === "/collect") return await collect(req, env);
      if (req.method === "GET" && url.pathname === "/export") return await exportRows(req, env, url);
      if (req.method === "GET" && url.pathname === "/stats") return await stats(req, env, url);
      if (req.method === "GET" && url.pathname === "/health") return text("ok");
    } catch (e) {
      return json({ error: "server" }, 500);
    }
    return text("not found", 404);
  },
};

// ── 수집(공개·익명 쓰기) ──────────────────────────────────────────────────────
async function collect(req, env) {
  const clen = +(req.headers.get("content-length") || 0);
  if (clen > MAX_BODY) return json({ error: "too large" }, 413);
  let raw;
  try { raw = await req.text(); } catch { return json({ error: "read" }, 400); }
  if (raw.length > MAX_BODY) return json({ error: "too large" }, 413);
  let o;
  try { o = JSON.parse(raw); } catch { return json({ error: "json" }, 400); }
  if (!o || o.app !== APP_TAG) return json({ error: "tag" }, 400);   // 앱 태그 불일치 = 소음
  const r = sanitize(o);
  if (!r) return json({ error: "shape" }, 400);                      // 설치 ID 없음/형식 오류 등
  await env.DB.prepare(
    `INSERT INTO sessions
      (ts, install_id, app_build, os, transport, encoder, priority, dur_s, lan,
       screen_w, screen_h, fps_avg, fps_p10, rtt_p50, rtt_p90, loss_pct, kbps_avg, kbps_p90,
       res_changes, hold_activations, rung_100_s, rung_50_s, rung_33_s, rung_25_s,
       ev_lowfps, ev_starve, ev_hardstall, ev_up, ev_policy, schema, raw)
     VALUES (?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?, ?,?,?,?,?,?,?)`
  ).bind(
    Date.now(), r.install_id, r.app_build, r.os, r.transport, r.encoder, r.priority, r.dur_s, r.lan,
    r.screen_w, r.screen_h, r.fps_avg, r.fps_p10, r.rtt_p50, r.rtt_p90, r.loss_pct, r.kbps_avg, r.kbps_p90,
    r.res_changes, r.hold_activations, r.rung_100_s, r.rung_50_s, r.rung_33_s, r.rung_25_s,
    r.ev_lowfps, r.ev_starve, r.ev_hardstall, r.ev_up, r.ev_policy, r.schema, JSON.stringify(r)
  ).run();
  return json({ ok: true });
}

// 화이트리스트 — 들어온 것 중 아는 숫자/짧은 열거값만 취하고 나머지는 전부 버린다(개인정보가 섞여 와도 저장 안 됨).
function sanitize(o) {
  const id = shortStr(o.install_id, 40);
  if (!id || !/^[0-9a-f-]{8,40}$/i.test(id)) return null;           // 무작위 설치 ID(16진수/하이픈)만
  const enumIn = (v, allow, def) => (allow.includes(v) ? v : def);
  return {
    install_id: id,
    app_build: shortStr(o.app_build, 24) || "",
    os: enumIn(o.os, ["win", "linux", "mac"], ""),
    transport: enumIn(o.transport, ["webrtc", "ws"], ""),
    encoder: shortStr(o.encoder, 24) || "",                         // h264_nvenc 등(짧은 영숫자)
    priority: enumIn(o.priority, ["smooth", "balanced", "sharp"], ""),
    dur_s: num(o.dur_s, 0, 86400),
    lan: o.lan ? 1 : 0,
    screen_w: int(o.screen_w, 0, 16384), screen_h: int(o.screen_h, 0, 16384),
    fps_avg: num(o.fps_avg, 0, 240), fps_p10: num(o.fps_p10, 0, 240),
    rtt_p50: num(o.rtt_p50, 0, 60000), rtt_p90: num(o.rtt_p90, 0, 60000),
    loss_pct: num(o.loss_pct, 0, 100),
    kbps_avg: num(o.kbps_avg, 0, 1e9), kbps_p90: num(o.kbps_p90, 0, 1e9),
    res_changes: int(o.res_changes, 0, 1e6),
    hold_activations: int(o.hold_activations, 0, 1e6),
    rung_100_s: num(o.rung_100_s, 0, 86400), rung_50_s: num(o.rung_50_s, 0, 86400),
    rung_33_s: num(o.rung_33_s, 0, 86400), rung_25_s: num(o.rung_25_s, 0, 86400),
    ev_lowfps: int(o.ev_lowfps, 0, 1e6), ev_starve: int(o.ev_starve, 0, 1e6),
    ev_hardstall: int(o.ev_hardstall, 0, 1e6), ev_up: int(o.ev_up, 0, 1e6),
    ev_policy: int(o.ev_policy, 0, 1e6),
    schema: int(o.schema, 0, 1000),
  };
}
function num(v, lo, hi) { v = typeof v === "number" && isFinite(v) ? v : 0; return Math.min(hi, Math.max(lo, v)); }
function int(v, lo, hi) { return Math.round(num(v, lo, hi)); }
function shortStr(v, n) { return typeof v === "string" ? v.slice(0, n).replace(/[^\x20-\x7e]/g, "") : ""; }

// ── 내보내기(비밀 토큰 필요 — 분석 PC 전용) ───────────────────────────────────
async function exportRows(req, env, url) {
  if (!auth(req, env, url)) return json({ error: "unauthorized" }, 401);
  const limit = Math.min(10000, Math.max(1, +(url.searchParams.get("limit") || 2000)));
  const since = +(url.searchParams.get("since") || 0);
  const rs = await env.DB.prepare(
    "SELECT * FROM sessions WHERE ts > ? ORDER BY ts DESC LIMIT ?"
  ).bind(since, limit).all();
  const fmt = url.searchParams.get("format") || "json";
  if (fmt === "csv") return csv(rs.results || []);
  return json({ rows: rs.results || [], count: (rs.results || []).length });
}

async function stats(req, env, url) {
  if (!auth(req, env, url)) return json({ error: "unauthorized" }, 401);
  const rs = await env.DB.prepare(
    `SELECT app_build, encoder, COUNT(*) n,
            AVG(res_changes) avg_res_changes, AVG(dur_s) avg_dur,
            AVG(fps_avg) avg_fps, AVG(rtt_p90) avg_rtt_p90, AVG(loss_pct) avg_loss
     FROM sessions GROUP BY app_build, encoder ORDER BY app_build DESC, n DESC`
  ).all();
  return json({ groups: rs.results || [] });
}

// 상수 시간 비교(길이 노출 최소화) — 토큰은 EXPORT_TOKEN 비밀, ?token= 또는 Authorization: Bearer
function auth(req, env, url) {
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

// ── 응답 헬퍼 ────────────────────────────────────────────────────────────────
function json(o, status = 200) {
  return new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}
function text(s, status = 200) { return new Response(s, { status, headers: { "content-type": "text/plain; charset=utf-8" } }); }
function csv(rows) {
  if (!rows.length) return text("");
  const cols = Object.keys(rows[0]);
  const esc = (v) => { v = v == null ? "" : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  const body = [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
  return new Response(body, { headers: { "content-type": "text/csv; charset=utf-8" } });
}
