// DW Remote 게이트 Worker (Cloudflare Workers + D1) — 라이선스(tier) + 글로벌/버전/설치 활성화 플래그(원격 kill switch)
// ─────────────────────────────────────────────────────────────────────────────
// 역할: 배포본(exe)이 켜질 때 POST /gate 로 물어보면, "지금 돌아도 되는가(active)"와 "등급(tier)"을
//  Ed25519 로 서명해 돌려준다. 클라는 exe 에 박힌 공개키로 서명을 검증한다(가짜 서버가 판정을 위조 못 함).
//
// 설계 근거(논의 2026-10-02, [[license-and-kill-switch]]):
//  - 라이선스와 kill 은 같은 메커니즘(물어봄 → 서명된 판정 → 동작 허용/차단) → 한 Worker.
//  - v1 라이선스 = 전원 "free"(키 입력 없음·첫 실행 자동 등록). tier 필드만 둬서 나중에 유료 얹기 쉽게.
//  - kill 은 전체(global_active) + 버전별(killed_versions) + 설치별(installs.status) 3단.
//  - 서명 필수: 없으면 가짜 서버(MITM·DNS)로 kill 위조/무력화 가능. 개인키는 Worker 비밀에만, exe 엔 공개키만.
//  - fail-open 은 "클라" 책임: 서버에 못 물어보면 클라가 그냥 실행(유예는 보류). 여기선 늘 솔직한 판정만 서명해 돌려줌.
//  - 익명 쓰기 남용 방지: 본문 상한·앱태그·install_id 형식·nonce 길이 제한(+ 대시보드 Rate Limiting 권장, README).
//
// 배포: README.md (d1 create→schema→secret put GATE_KEY(PKCS8 b64)·GATE_ADMIN_TOKEN→deploy). 공개키는 keygen.py 가 앱에 박을 값을 출력.

const MAX_BODY = 2048;          // /gate 본문은 작다(수백 바이트) — 초과 거부
const APP_TAG = "dwremote1";    // 비밀 아님 — 봇/스캐너 소음 거르기
const SIG_VER = "dwgate1";      // 서명 메시지 포맷 버전(클라와 합의) — 바꾸면 클라도 같이

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (req.method === "POST" && url.pathname === "/gate") return await gate(req, env);
      if (req.method === "GET" && url.pathname === "/health") return text("ok");
      if (req.method === "POST" && url.pathname === "/admin/flag") return await adminFlag(req, env, url);
      if (req.method === "POST" && url.pathname === "/admin/install") return await adminInstall(req, env, url);
      if (req.method === "GET" && url.pathname === "/admin/installs") return await adminList(req, env, url);
    } catch (e) {
      return json({ error: "server" }, 500);
    }
    return text("not found", 404);
  },
};

// ── 판정(공개) ────────────────────────────────────────────────────────────────
async function gate(req, env) {
  const clen = +(req.headers.get("content-length") || 0);
  if (clen > MAX_BODY) return json({ error: "too large" }, 413);
  let raw;
  try { raw = await req.text(); } catch { return json({ error: "read" }, 400); }
  if (raw.length > MAX_BODY) return json({ error: "too large" }, 413);
  let o;
  try { o = JSON.parse(raw); } catch { return json({ error: "json" }, 400); }
  if (!o || o.app !== APP_TAG) return json({ error: "tag" }, 400);

  const install_id = shortStr(o.install_id, 40);
  if (!install_id || !/^[0-9a-f-]{8,40}$/i.test(install_id)) return json({ error: "install_id" }, 400);
  const build = shortStr(o.build, 24);
  const os = enumIn(o.os, ["win", "linux", "mac"], "");
  const nonce = shortStr(o.nonce, 64);
  if (!nonce || nonce.length < 8) return json({ error: "nonce" }, 400);   // 클라가 매 호출 새로 — 재생 방지

  const ts = Date.now();
  // 설치 등록부 upsert(처음 보면 생성=자동 등록·free). 기존이면 마지막 접속·버전 갱신(상태·등급은 유지).
  await env.DB.prepare(
    `INSERT INTO installs (install_id, first_seen, last_seen, build, os, status, tier)
     VALUES (?,?,?,?,?, 'active','free')
     ON CONFLICT(install_id) DO UPDATE SET last_seen=excluded.last_seen, build=excluded.build, os=excluded.os`
  ).bind(install_id, ts, ts, build, os).run();

  const inst = await env.DB.prepare("SELECT status, tier FROM installs WHERE install_id=?").bind(install_id).first();
  const cfg = await loadConfig(env);
  const tier = (inst && inst.tier) || "free";

  // active = 전체 켜짐 AND 이 설치 안 막힘 AND 이 버전 안 막힘 AND (최소버전 있으면 충족)
  let active = true, reason = "";
  if (cfg.global_active !== "1") { active = false; reason = "global"; }
  else if (inst && inst.status === "revoked") { active = false; reason = "install"; }
  else if (build && cfg.killed_versions.includes(build)) { active = false; reason = "version"; }
  else if (cfg.min_version && build && cmpBuild(build, cfg.min_version) < 0) { active = false; reason = "min_version"; }

  const a = active ? "1" : "0";
  const msg = [SIG_VER, install_id, build, a, tier, ts, nonce].join("|");  // 클라가 똑같이 조립해 검증
  const sig = await sign(env, msg);
  return json({ v: SIG_VER, active, tier, ts, nonce, reason, sig });
}

async function loadConfig(env) {
  const rs = await env.DB.prepare("SELECT k, v FROM gate_config").all();
  const m = {};
  for (const r of (rs.results || [])) m[r.k] = r.v;
  return {
    global_active: m.global_active == null ? "1" : m.global_active,   // 기본 켜짐(기록 없으면 active)
    killed_versions: (m.killed_versions || "").split(",").map(s => s.trim()).filter(Boolean),
    min_version: (m.min_version || "").trim(),
  };
}

// ── 관리(토큰 필요) ────────────────────────────────────────────────────────────
async function adminFlag(req, env, url) {
  if (!auth(req, env, url)) return json({ error: "unauthorized" }, 401);
  let o; try { o = JSON.parse(await req.text()); } catch { return json({ error: "json" }, 400); }
  const sets = [];
  if (o.global_active != null) sets.push(["global_active", o.global_active ? "1" : "0"]);
  if (o.killed_versions != null) sets.push(["killed_versions", String(o.killed_versions).slice(0, 2000)]);
  if (o.min_version != null) sets.push(["min_version", shortStr(o.min_version, 24)]);
  for (const [k, v] of sets) {
    await env.DB.prepare("INSERT INTO gate_config (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(k, v).run();
  }
  return json({ ok: true, set: sets.map(s => s[0]) });
}

async function adminInstall(req, env, url) {
  if (!auth(req, env, url)) return json({ error: "unauthorized" }, 401);
  let o; try { o = JSON.parse(await req.text()); } catch { return json({ error: "json" }, 400); }
  const id = shortStr(o.install_id, 40);
  if (!id) return json({ error: "install_id" }, 400);
  const status = o.status != null ? enumIn(o.status, ["active", "revoked"], "active") : null;
  const tier = o.tier != null ? shortStr(o.tier, 24) : null;
  if (status != null) await env.DB.prepare("UPDATE installs SET status=? WHERE install_id=?").bind(status, id).run();
  if (tier != null) await env.DB.prepare("UPDATE installs SET tier=? WHERE install_id=?").bind(tier, id).run();
  return json({ ok: true });
}

async function adminList(req, env, url) {
  if (!auth(req, env, url)) return json({ error: "unauthorized" }, 401);
  const limit = Math.min(5000, Math.max(1, +(url.searchParams.get("limit") || 1000)));
  const rs = await env.DB.prepare("SELECT * FROM installs ORDER BY last_seen DESC LIMIT ?").bind(limit).all();
  const cfg = await loadConfig(env);
  return json({ config: cfg, installs: rs.results || [], count: (rs.results || []).length });
}

// ── Ed25519 서명(개인키=Worker 비밀 GATE_KEY, PKCS8 base64) ─────────────────────
let _KEY = null;   // isolate 당 1회 import 캐시
async function sign(env, msg) {
  if (!_KEY) {
    const pkcs8 = b64ToBytes(env.GATE_KEY);
    _KEY = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  }
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, _KEY, new TextEncoder().encode(msg));
  return bytesToB64(new Uint8Array(sig));
}

// 상수 시간 비교 — 관리 토큰(GATE_ADMIN_TOKEN), ?token= 또는 Authorization: Bearer
function auth(req, env, url) {
  const want = env.GATE_ADMIN_TOKEN || "";
  if (!want) return false;
  let got = url.searchParams.get("token") || "";
  const h = req.headers.get("authorization") || "";
  if (!got && h.startsWith("Bearer ")) got = h.slice(7);
  if (got.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= got.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}

// ── 유틸 ──────────────────────────────────────────────────────────────────────
function enumIn(v, allow, def) { return allow.includes(v) ? v : def; }
function shortStr(v, n) { return typeof v === "string" ? v.slice(0, n).replace(/[^\x20-\x7e]/g, "") : ""; }
// 빌드 번호 비교 "YYYYMMDD.HHMM" — 문자열 비교로 충분(고정 자릿수)하지만 안전하게 숫자 쌍으로
function cmpBuild(a, b) {
  const p = s => s.split(".").map(x => parseInt(x, 10) || 0);
  const [a1, a2] = p(a), [b1, b2] = p(b);
  return a1 !== b1 ? a1 - b1 : a2 - b2;
}
function b64ToBytes(s) { const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
function bytesToB64(u) { let s = ""; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
function json(o, status = 200) { return new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8" } }); }
function text(s, status = 200) { return new Response(s, { status, headers: { "content-type": "text/plain; charset=utf-8" } }); }
