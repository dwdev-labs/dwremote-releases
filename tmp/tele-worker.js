// DW Remote 성능 텔레메트리 수집 Worker (Cloudflare Workers + D1) — 2단 동의(2026-10-02). [[telemetry-collection]]
// ─────────────────────────────────────────────────────────────────────────────
// 역할: 배포본이 보내는 "숫자만" 세션 요약을 POST /collect 로 받아 D1(intake)에 쌓는다. 읽기(/export·/stats)는 EXPORT_TOKEN 비밀.
//  Cron Worker 가 intake→safe D1 로 옮기며 비운다(운영자는 safe 를 분석). exe 엔 '보낼 주소'만(비밀 아님).
//
// 2단 동의(사용자 결정):
//  · 티어1(익명·무동의·고지+opt-out): 아래 숫자들. install_id = 세션별 무작위(추적 불가), 서버 티어2 동의면 서버 지속 ID.
//  · 티어2(동의): 서버(s_*: GPU/CPU/모니터/DPI)·뷰어(v_*: OS/창크기/DPR/보기방식)·지역(country) — **해당 쪽 동의 있을 때만** 저장.
//    country 는 앱이 IP 를 안 보냄 → Cloudflare 가 요청에서 준 국가코드(request.cf.country)를, 둘 중 하나라도 티어2 동의일 때만 저장.
//  · 개인정보(화면·IP원본·PC이름·비번·파일명·클립보드)는 애초에 안 받는다(sanitize 화이트리스트가 버림).
//
// 남용 방지(익명 공개 쓰기): 본문 크기 상한 · 앱태그 · 숫자/짧은열거 화이트리스트 (+ 대시보드 Rate Limiting 권장, README).

const MAX_BODY = 8192;
const APP_TAG = "dwremote1";
const SCHEMA_VER = 2;

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
  if (!o || o.app !== APP_TAG) return json({ error: "tag" }, 400);
  const country = (req.cf && req.cf.country) ? String(req.cf.country) : "";   // CF 엣지가 준 국가(앱은 IP 안 보냄)
  const r = sanitize(o, country);
  if (!r) return json({ error: "shape" }, 400);
  await insert(env.DB, r);
  return json({ ok: true });
}

async function insert(db, r) {
  await db.prepare(
    `INSERT INTO sessions
      (ts, install_id, app_build, os, transport, encoder, priority, dur_s, lan,
       screen_w, screen_h, fps_avg, fps_p10, rtt_p50, rtt_p90, loss_pct, kbps_avg, kbps_p90,
       res_changes, hold_activations, rung_100_s, rung_50_s, rung_33_s, rung_25_s,
       ev_lowfps, ev_starve, ev_hardstall, ev_up, ev_policy, schema,
       s_tier2, c_tier2, s_gpu, s_cpu, s_mon_count, s_mon_w, s_mon_h, s_dpi, country,
       v_os, v_w, v_h, v_dpr, v_mode, c_install_id, raw)
     VALUES (?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?, ?,?,?,?,?,?,
             ?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?)`
  ).bind(
    Date.now(), r.install_id, r.app_build, r.os, r.transport, r.encoder, r.priority, r.dur_s, r.lan,
    r.screen_w, r.screen_h, r.fps_avg, r.fps_p10, r.rtt_p50, r.rtt_p90, r.loss_pct, r.kbps_avg, r.kbps_p90,
    r.res_changes, r.hold_activations, r.rung_100_s, r.rung_50_s, r.rung_33_s, r.rung_25_s,
    r.ev_lowfps, r.ev_starve, r.ev_hardstall, r.ev_up, r.ev_policy, r.schema,
    r.s_tier2, r.c_tier2, r.s_gpu, r.s_cpu, r.s_mon_count, r.s_mon_w, r.s_mon_h, r.s_dpi, r.country,
    r.v_os, r.v_w, r.v_h, r.v_dpr, r.v_mode, r.c_install_id, JSON.stringify(r)
  ).run();
}

// 화이트리스트 — 아는 숫자/짧은 열거값만. 티어2 필드는 해당 동의가 있을 때만(과수집 방지).
function sanitize(o, country) {
  const id = shortStr(o.install_id, 40);
  if (!id || !/^[0-9a-f-]{8,40}$/i.test(id)) return null;        // 무작위 설치 ID(16진/하이픈)만
  const s2 = o.s_tier2 ? 1 : 0;
  const c2 = o.c_tier2 ? 1 : 0;
  const hexId = (v) => { v = shortStr(v, 40); return /^[0-9a-f-]{8,40}$/i.test(v) ? v : null; };
  return {
    install_id: id,
    app_build: shortStr(o.app_build, 24) || "",
    os: enumIn(o.os, ["win", "linux", "mac"], ""),
    transport: enumIn(o.transport, ["webrtc", "ws"], ""),
    encoder: shortStr(o.encoder, 24) || "",
    priority: enumIn(o.priority, ["smooth", "balanced", "sharp"], ""),
    dur_s: num(o.dur_s, 0, 86400),
    lan: o.lan ? 1 : 0,
    screen_w: int(o.screen_w, 0, 16384), screen_h: int(o.screen_h, 0, 16384),
    fps_avg: num(o.fps_avg, 0, 240), fps_p10: num(o.fps_p10, 0, 240),
    rtt_p50: num(o.rtt_p50, 0, 60000), rtt_p90: num(o.rtt_p90, 0, 60000),
    loss_pct: num(o.loss_pct, 0, 100),
    kbps_avg: num(o.kbps_avg, 0, 1e9), kbps_p90: num(o.kbps_p90, 0, 1e9),
    res_changes: int(o.res_changes, 0, 1e6), hold_activations: int(o.hold_activations, 0, 1e6),
    rung_100_s: num(o.rung_100_s, 0, 86400), rung_50_s: num(o.rung_50_s, 0, 86400),
    rung_33_s: num(o.rung_33_s, 0, 86400), rung_25_s: num(o.rung_25_s, 0, 86400),
    ev_lowfps: int(o.ev_lowfps, 0, 1e6), ev_starve: int(o.ev_starve, 0, 1e6),
    ev_hardstall: int(o.ev_hardstall, 0, 1e6), ev_up: int(o.ev_up, 0, 1e6), ev_policy: int(o.ev_policy, 0, 1e6),
    schema: int(o.schema, 0, 1000) || SCHEMA_VER,
    // ── 티어2 ──
    s_tier2: s2, c_tier2: c2,
    s_gpu: s2 ? (shortStr(o.s_gpu, 48) || null) : null,
    s_cpu: s2 ? (shortStr(o.s_cpu, 48) || null) : null,
    s_mon_count: s2 ? int(o.s_mon_count, 0, 16) : null,
    s_mon_w: s2 ? int(o.s_mon_w, 0, 16384) : null,
    s_mon_h: s2 ? int(o.s_mon_h, 0, 16384) : null,
    s_dpi: s2 ? int(o.s_dpi, 0, 2000) : null,
    country: (s2 || c2) ? (shortStr(country, 8) || null) : null,     // CF 국가(앱이 IP 안 보냄), 티어2 때만
    v_os: c2 ? enumIn(o.v_os, ["win", "linux", "mac"], null) : null,
    v_w: c2 ? int(o.v_w, 0, 16384) : null,
    v_h: c2 ? int(o.v_h, 0, 16384) : null,
    v_dpr: c2 ? num(o.v_dpr, 0, 8) : null,
    v_mode: c2 ? enumIn(o.v_mode, ["fit", "width", "actual", "zoom"], null) : null,
    c_install_id: c2 ? hexId(o.c_install_id) : null,
  };
}
function num(v, lo, hi) { v = typeof v === "number" && isFinite(v) ? v : 0; return Math.min(hi, Math.max(lo, v)); }
function int(v, lo, hi) { return Math.round(num(v, lo, hi)); }
function shortStr(v, n) { return typeof v === "string" ? v.slice(0, n).replace(/[^\x20-\x7e]/g, "") : ""; }
function enumIn(v, allow, def) { return allow.includes(v) ? v : def; }

// ── 내보내기(비밀 토큰 필요) ───────────────────────────────────────────────────
async function exportRows(req, env, url) {
  if (!auth(req, env, url)) return json({ error: "unauthorized" }, 401);
  const limit = Math.min(10000, Math.max(1, +(url.searchParams.get("limit") || 2000)));
  const since = +(url.searchParams.get("since") || 0);
  const rs = await env.DB.prepare("SELECT * FROM sessions WHERE ts > ? ORDER BY ts DESC LIMIT ?").bind(since, limit).all();
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
function json(o, status = 200) { return new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8" } }); }
function text(s, status = 200) { return new Response(s, { status, headers: { "content-type": "text/plain; charset=utf-8" } }); }
function csv(rows) {
  if (!rows.length) return text("");
  const cols = Object.keys(rows[0]);
  const esc = (v) => { v = v == null ? "" : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  const body = [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
  return new Response(body, { headers: { "content-type": "text/csv; charset=utf-8" } });
}
