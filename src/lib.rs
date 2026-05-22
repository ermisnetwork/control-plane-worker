//! HLS Playlist Fan-out with WebSocket Viewer Support
//!
//! Architecture (hash routing + 503 overflow):
//!   - LlHlsDO  : LL-HLS blocking (playlist.m3u8) + WS viewer push.
//!   - SimpleDO : simple.m3u8 blocking + WS viewer push.
//!
//! Worker entry routes:
//!   Software streams:
//!     /hls/{app}/{sid}/master.m3u8
//!     /hls/{app}/{sid}[/{rendition}]/playlist.m3u8
//!     /hls/{app}/{sid}[/{rendition}]/simple.m3u8
//!     /hls/{app}/{sid}[/{rendition}]/playlist-ws
//!     /hls/{app}/{sid}[/{rendition}]/simple-ws
//!
//!   Browser streams:
//!     /browser/hls/{uuid}/master.m3u8
//!     /browser/hls/{uuid}[/{rendition}]/playlist.m3u8
//!     /browser/hls/{uuid}[/{rendition}]/simple.m3u8
//!     /browser/hls/{uuid}[/{rendition}]/playlist-ws
//!     /browser/hls/{uuid}[/{rendition}]/simple-ws
//!
//! Routing:
//!   master.m3u8   → hash(IP) % MAX_SHARDS → LlHlsDO[shard_id] (blocking HTTP)
//!   playlist.m3u8 → hash(IP) % MAX_SHARDS → LlHlsDO[shard_id] (blocking HTTP)
//!   simple.m3u8   → hash(IP) % MAX_SHARDS → SimpleDO[shard_id] (blocking HTTP)
//!   playlist-ws   → LlHlsDO[hash shard] (WebSocket viewer push)
//!   simple-ws     → SimpleDO[hash shard] (WebSocket viewer push)
//!
//! Stream key format:
//!   Software: "{app}:{sid}" or "{app}:{sid}:{rendition}" ("original" maps to "{app}:{sid}")
//!   Browser:  "browser:{uuid}" (rendition path is accepted but not part of the stream key)
//!
//! WebSocket viewer protocol (DO → client):
//!   { "type": "part",   "msn": N, "part": N, "playlist": "..." }
//!   { "type": "simple", "seq": N, "playlist": "..." }
//!   { "type": "end" }
//!
//! Viewer WS messages (client → DO): ignored (one-way push only).

use futures_channel::oneshot;
use futures_util::StreamExt;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, rc::Rc};
use worker::*;

// ── Tuning constants ──────────────────────────────────────────────────────────
/// Alarm timeout: drain all HTTP waiters if origin WS doesn't respond in time.
const VIEWER_TIMEOUT_MS: i64 = 5_000;
/// Max concurrent HTTP waiters per shard before returning 503.
const MAX_WAITERS_PER_SHARD: u32 = 500;
const H_ORIGIN_BASE_URL: &str = "X-Origin-Base-Url";
const H_ORIGIN_NODE_ID: &str = "X-Origin-Node-Id";
const H_ORIGIN_STREAM_SESSION_ID: &str = "X-Origin-Stream-Session-Id";
const H_ORIGIN_ROUTE_VERSION: &str = "X-Origin-Route-Version";

// ── Message types ─────────────────────────────────────────────────────────────

/// Messages received from origin via websocket.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
enum OriginMsg {
    Part {
        msn: u64,
        part: u32,
        playlist: String,
    },
    Simple {
        seq: u64,
        playlist: String,
    },
    Master {
        playlist: String,
    },
    End,
}

/// Messages sent from DO back to origin (reverse).
#[derive(Serialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
enum DoMsg {
    /// Viewer count for a specific Part cycle (HTTP waiters + WS viewers).
    Viewers { count: u32, msn: u64, part: u32 },
}

/// Messages pushed from DO to viewer WebSocket clients.
#[derive(Serialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ViewerMsg<'a> {
    Part {
        msn: u64,
        part: u32,
        playlist: &'a str,
    },
    Simple {
        seq: u64,
        playlist: &'a str,
    },
    End,
}

#[derive(Deserialize, Default)]
struct HlsQuery {
    #[serde(rename = "_HLS_msn", default)]
    msn: u64,
    #[serde(rename = "_HLS_part", default)]
    part: u32,
}

#[derive(Debug)]
enum JwtAuthError {
    MissingConfig,
    Unauthorized,
    Forbidden,
}

#[derive(Debug, Clone, Deserialize)]
struct PlaybackClaims {
    stream_id: String,
    stream_session_id: String,
    node_id: String,
    origin_base_url: String,
    route_version: u64,
    scope: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OriginRoute {
    origin_base_url: String,
    node_id: String,
    stream_session_id: String,
    route_version: u64,
}

#[derive(Debug, Clone)]
struct ParsedRequest {
    token: String,
    stream_id: String,
    stream_key: String,
    playlist_type: &'static str,
}

// ── Worker entry ──────────────────────────────────────────────────────────────
#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // CORS preflight
    if req.method() == Method::Options {
        let h = Headers::new();
        h.set("Access-Control-Allow-Origin", "*")?;
        h.set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
        h.set("Access-Control-Allow-Headers", "*")?;
        h.set("Access-Control-Max-Age", "86400")?;
        return Response::empty().map(|r| r.with_headers(h));
    }

    // Per-PoP namespacing.
    let colo = req
        .cf()
        .map(|cf| cf.colo())
        .unwrap_or_else(|| "XX".to_string());

    let path = req.path();
    let Some(parsed) = parse_playlist_path(&path) else {
        return cors_error("Not found", 404);
    };
    if parsed.playlist_type == "media" {
        return cors_error("Media objects are served by CDN, not this Worker", 404);
    }
    let claims = match verify_playback_token(&parsed.token, &env) {
        Ok(claims) => claims,
        Err(e) => {
            return match e {
                JwtAuthError::MissingConfig => cors_error("JWT auth is not configured", 500),
                JwtAuthError::Unauthorized => cors_error("Unauthorized", 401),
                JwtAuthError::Forbidden => cors_error("Forbidden", 403),
            };
        }
    };
    if let Err(e) = authorize_parsed_request(&parsed, &claims) {
        return match e {
            JwtAuthError::MissingConfig => cors_error("JWT auth is not configured", 500),
            JwtAuthError::Unauthorized => cors_error("Unauthorized", 401),
            JwtAuthError::Forbidden => cors_error("Forbidden", 403),
        };
    }
    let stream_key = parsed.stream_key.clone();
    let url = req.url()?.to_string();
    let route = OriginRoute {
        origin_base_url: normalize_origin_base(&claims.origin_base_url),
        node_id: claims.node_id.clone(),
        stream_session_id: claims.stream_session_id.clone(),
        route_version: claims.route_version,
    };

    let ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let max_shards = get_max_shards(&env);
    let start_shard = djb2_hash(&ip) % max_shards;

    match parsed.playlist_type {
        // ── Blocking HTTP: LL-HLS ──────────────────────────────────────────────
        "llhls" => {
            let ll_ns = env.durable_object("LL_HLS_DO")?;
            for attempt in 0..max_shards {
                let shard_id = (start_shard + attempt) % max_shards;
                let ll_id =
                    ll_ns.id_from_name(&format!("{}:ll:{}:{}", stream_key, colo, shard_id))?;
                let ll_stub = ll_id.get_stub()?;
                let fwd = Headers::new();
                fwd.set("X-Stream-Key", &stream_key)?;
                set_origin_route_headers(&fwd, &route)?;
                let do_req = Request::new_with_init(
                    &url,
                    RequestInit::new()
                        .with_headers(fwd)
                        .with_method(Method::Get),
                )?;
                match ll_stub.fetch_with_request(do_req).await {
                    Ok(resp) if resp.status_code() == 503 => continue,
                    Ok(resp) => return add_cors(resp),
                    Err(e) => return cors_error(&format!("LlHlsDO error: {}", e), 502),
                }
            }
            cors_error("All LL-HLS shards full", 503)
        }

        // ── Blocking HTTP: simple.m3u8 ─────────────────────────────────────────
        "simple" => {
            let simple_ns = env.durable_object("SIMPLE_DO")?;
            for attempt in 0..max_shards {
                let shard_id = (start_shard + attempt) % max_shards;
                let simple_id = simple_ns
                    .id_from_name(&format!("{}:simple:{}:{}", stream_key, colo, shard_id))?;
                let simple_stub = simple_id.get_stub()?;
                let fwd = Headers::new();
                fwd.set("X-Stream-Key", &stream_key)?;
                set_origin_route_headers(&fwd, &route)?;
                let do_req = Request::new_with_init(
                    &url,
                    RequestInit::new()
                        .with_headers(fwd)
                        .with_method(Method::Get),
                )?;
                match simple_stub.fetch_with_request(do_req).await {
                    Ok(resp) if resp.status_code() == 503 => continue,
                    Ok(resp) => return add_cors(resp),
                    Err(e) => return cors_error(&format!("SimpleDO error: {}", e), 502),
                }
            }
            cors_error("All Simple shards full", 503)
        }

        // ── Blocking HTTP: master.m3u8 ───────────────────────────────────────────
        "master" => {
            let ll_ns = env.durable_object("LL_HLS_DO")?;
            for attempt in 0..max_shards {
                let shard_id = (start_shard + attempt) % max_shards;
                let ll_id =
                    ll_ns.id_from_name(&format!("{}:ll:{}:{}", stream_key, colo, shard_id))?;
                let ll_stub = ll_id.get_stub()?;
                let fwd = Headers::new();
                fwd.set("X-Stream-Key", &stream_key)?;
                fwd.set("X-Playlist-Type", "master")?;
                set_origin_route_headers(&fwd, &route)?;
                let do_req = Request::new_with_init(
                    &url,
                    RequestInit::new()
                        .with_headers(fwd)
                        .with_method(Method::Get),
                )?;
                match ll_stub.fetch_with_request(do_req).await {
                    Ok(resp) if resp.status_code() == 503 => continue,
                    Ok(resp) => return add_cors(resp),
                    Err(e) => return cors_error(&format!("LlHlsDO master error: {}", e), 502),
                }
            }
            cors_error("All shards full", 503)
        }

        // ── WebSocket viewer: playlist-ws ──────────────────────────────────────
        // Route: /hls/{app}/{sid}[/{rend}]/playlist-ws
        // No overflow needed — WS connections are lightweight and sticky per shard.
        "llhls-ws" => {
            let ll_ns = env.durable_object("LL_HLS_DO")?;
            let shard_id = start_shard;
            let ll_id = ll_ns.id_from_name(&format!("{}:ll:{}:{}", stream_key, colo, shard_id))?;
            let ll_stub = ll_id.get_stub()?;
            let fwd = copy_ws_headers(&req, &stream_key, true)?;
            set_origin_route_headers(&fwd, &route)?;
            let do_req = Request::new_with_init(
                &url,
                RequestInit::new()
                    .with_headers(fwd)
                    .with_method(Method::Get),
            )?;
            ll_stub.fetch_with_request(do_req).await.map(add_cors_ws)
        }

        // ── WebSocket viewer: simple-ws ────────────────────────────────────────
        // Route: /hls/{app}/{sid}[/{rend}]/simple-ws
        "simple-ws" => {
            let simple_ns = env.durable_object("SIMPLE_DO")?;
            let shard_id = start_shard;
            let simple_id =
                simple_ns.id_from_name(&format!("{}:simple:{}:{}", stream_key, colo, shard_id))?;
            let simple_stub = simple_id.get_stub()?;
            let fwd = copy_ws_headers(&req, &stream_key, true)?;
            set_origin_route_headers(&fwd, &route)?;
            let do_req = Request::new_with_init(
                &url,
                RequestInit::new()
                    .with_headers(fwd)
                    .with_method(Method::Get),
            )?;
            simple_stub
                .fetch_with_request(do_req)
                .await
                .map(add_cors_ws)
        }

        _ => cors_error("Unknown playlist type", 404),
    }
}

fn add_cors(resp: Response) -> Result<Response> {
    let h = resp.headers().clone();
    h.set("Access-Control-Allow-Origin", "*")?;
    Ok(resp.with_headers(h))
}

/// For WebSocket upgrade responses, don't add CORS (WS doesn't use CORS).
fn add_cors_ws(resp: Response) -> Response {
    resp
}

fn cors_error(msg: &str, status: u16) -> Result<Response> {
    let h = Headers::new();
    let _ = h.set("Access-Control-Allow-Origin", "*");
    Response::error(msg, status).map(|r| r.with_headers(h))
}

fn verify_playback_token(
    token: &str,
    env: &Env,
) -> std::result::Result<PlaybackClaims, JwtAuthError> {
    let secret = env
        .var("JWT_SECRET")
        .map_err(|_| JwtAuthError::MissingConfig)?
        .to_string();
    if secret.is_empty() {
        return Err(JwtAuthError::MissingConfig);
    }

    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.validate_aud = false;

    decode::<PlaybackClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| JwtAuthError::Unauthorized)
}

fn authorize_parsed_request(
    parsed: &ParsedRequest,
    claims: &PlaybackClaims,
) -> std::result::Result<(), JwtAuthError> {
    if parsed.stream_id != claims.stream_id {
        return Err(JwtAuthError::Forbidden);
    }
    if claims.stream_session_id.trim().is_empty()
        || claims.node_id.trim().is_empty()
        || claims.origin_base_url.trim().is_empty()
    {
        return Err(JwtAuthError::Forbidden);
    }
    let required_scope = match parsed.playlist_type {
        "master" => "hls:master",
        "llhls" | "llhls-ws" => "hls:playlist",
        "simple" | "simple-ws" => "hls:playlist",
        _ => return Err(JwtAuthError::Forbidden),
    };
    if !claims.scope.iter().any(|scope| scope == required_scope) {
        return Err(JwtAuthError::Forbidden);
    }
    Ok(())
}

fn normalize_origin_base(origin: &str) -> String {
    origin.trim_end_matches('/').to_string()
}

fn set_origin_route_headers(headers: &Headers, route: &OriginRoute) -> Result<()> {
    headers.set(H_ORIGIN_BASE_URL, &route.origin_base_url)?;
    headers.set(H_ORIGIN_NODE_ID, &route.node_id)?;
    headers.set(H_ORIGIN_STREAM_SESSION_ID, &route.stream_session_id)?;
    headers.set(H_ORIGIN_ROUTE_VERSION, &route.route_version.to_string())?;
    Ok(())
}

/// Build a forwarding Headers set for a viewer WebSocket upgrade.
///
/// Copies the standard WebSocket handshake headers from the incoming request
/// so the DO receives a proper HTTP/1.1 upgrade and can respond with 101.
/// Also adds our internal routing headers (X-Stream-Key, X-Viewer-WS).
fn copy_ws_headers(req: &Request, stream_key: &str, is_viewer_ws: bool) -> Result<Headers> {
    let src = req.headers();
    let dst = Headers::new();

    // WebSocket handshake fields (RFC 6455)
    for name in &[
        "Upgrade",
        "Connection",
        "Sec-WebSocket-Key",
        "Sec-WebSocket-Version",
        "Sec-WebSocket-Extensions",
        "Sec-WebSocket-Protocol",
    ] {
        if let Ok(Some(val)) = src.get(name) {
            let _ = dst.set(name, &val);
        }
    }
    // Ensure mandatory fields exist even if browser sent non-standard casing.
    if dst.get("Upgrade")?.is_none() {
        dst.set("Upgrade", "websocket")?;
    }
    if dst.get("Connection")?.is_none() {
        dst.set("Connection", "Upgrade")?;
    }

    // Internal routing headers
    dst.set("X-Stream-Key", stream_key)?;
    if is_viewer_ws {
        dst.set("X-Viewer-WS", "1")?;
    }
    Ok(dst)
}

// ══════════════════════════════════════════════════════════════════════════════
// LlHlsDO — LL-HLS playlist.m3u8
//
// Supports two modes per request:
//   1. Blocking HTTP (no X-Viewer-WS header): same as playlist-blocking-do.
//   2. WebSocket viewer (X-Viewer-WS: 1): upgrades connection, then receives
//      playlist pushes until stream ends or client disconnects.
// ══════════════════════════════════════════════════════════════════════════════
struct LlHlsInner {
    current_msn: u64,
    current_part: u32,
    playlist: String,
    stream_key: String,
    origin_route: Option<OriginRoute>,
    /// HTTP blocking waiters: (req_msn, req_part, sender)
    http_waiters: Vec<(u64, u32, oneshot::Sender<String>)>,
    /// Connected viewer WebSockets for push delivery
    viewer_ws: Vec<WebSocket>,
    initialized: bool,
    origin_connected: bool,
    should_clear: bool,
    /// Cached master.m3u8 content
    master_playlist: String,
    /// HTTP blocking waiters for master.m3u8
    master_waiters: Vec<oneshot::Sender<String>>,
}

impl Default for LlHlsInner {
    fn default() -> Self {
        Self {
            current_msn: 0,
            current_part: 0,
            playlist: String::new(),
            stream_key: String::new(),
            origin_route: None,
            http_waiters: Vec::new(),
            viewer_ws: Vec::new(),
            initialized: false,
            origin_connected: false,
            should_clear: false,
            master_playlist: String::new(),
            master_waiters: Vec::new(),
        }
    }
}

impl LlHlsInner {
    /// Total live viewer count: HTTP waiters + WS viewers.
    fn total_viewers(&self) -> u32 {
        (self.http_waiters.len() + self.viewer_ws.len()) as u32
    }

    /// Fan-out a message to all connected viewer WebSockets.
    /// Removes closed/errored connections automatically.
    fn fan_out_ws(&mut self, msg: &ViewerMsg) {
        if self.viewer_ws.is_empty() {
            return;
        }
        if let Ok(json) = serde_json::to_string(msg) {
            self.viewer_ws.retain(|ws| ws.send_with_str(&json).is_ok());
        }
    }

    /// Send End message and close all viewer WebSockets.
    fn close_all_viewer_ws(&mut self) {
        let end_msg = serde_json::to_string(&ViewerMsg::End).unwrap_or_default();
        for ws in self.viewer_ws.drain(..) {
            let _ = ws.send_with_str(&end_msg);
            let _ = ws.close::<&str>(None, None);
        }
    }
}

#[durable_object]
pub struct LlHlsDO {
    state: State,
    env: Env,
    inner: Rc<RefCell<LlHlsInner>>,
}

impl DurableObject for LlHlsDO {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            inner: Rc::new(RefCell::new(LlHlsInner::default())),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.ensure_initialized().await?;

        // ── Route: master.m3u8 blocking request ───────────────────────────────
        if req.headers().get("X-Playlist-Type")?.as_deref() == Some("master") {
            return self.handle_master_request(&req).await;
        }

        // ── Route: Viewer WebSocket upgrade ──────────────────────────────────
        if req.headers().get("X-Viewer-WS")?.as_deref() == Some("1") {
            return self.handle_viewer_ws(req).await;
        }

        // ── Route: Blocking HTTP playlist request ─────────────────────────────
        {
            let g = self.inner.borrow();
            if g.http_waiters.len() as u32 >= MAX_WAITERS_PER_SHARD {
                return Response::error("Shard full", 503);
            }
        }

        self.configure_origin_route(&req).await?;

        let query: HlsQuery = req.query().unwrap_or_default();
        let is_initial = req
            .url()
            .map(|u| !u.query().map(|q| q.contains("_HLS_msn")).unwrap_or(false))
            .unwrap_or(true);

        let (cur_msn, cur_part, playlist_now, should_clear) = {
            let g = self.inner.borrow();
            (
                g.current_msn,
                g.current_part,
                g.playlist.clone(),
                g.should_clear,
            )
        };

        if should_clear {
            let _ = self.state.storage().set_alarm(1).await;
            return ll_playlist_response(&playlist_now, 0);
        }

        if !playlist_now.is_empty()
            && (is_initial || satisfies(cur_msn, cur_part, query.msn, query.part))
        {
            return ll_playlist_response(&playlist_now, 0);
        }

        if let Err(e) = self.ensure_origin_ws().await {
            console_log!("[LlHlsDO] ensure_origin_ws error: {:?}", e);
        }

        let _ = self.state.storage().set_alarm(VIEWER_TIMEOUT_MS).await;

        let (tx, rx) = oneshot::channel::<String>();
        self.inner
            .borrow_mut()
            .http_waiters
            .push((query.msn, query.part, tx));

        match rx.await {
            Ok(playlist) => ll_playlist_response(&playlist, 0),
            Err(_) => {
                let pl = self.inner.borrow().playlist.clone();
                ll_playlist_response(&pl, 0)
            }
        }
    }

    async fn alarm(&self) -> Result<Response> {
        self.ensure_initialized().await?;
        let should_clear = self.inner.borrow().should_clear;
        let master = self.inner.borrow().master_playlist.clone();
        if should_clear {
            let _ = self.state.storage().delete_all().await;
            let mut g = self.inner.borrow_mut();
            g.playlist = String::new();
            g.should_clear = false;
            // Drain master waiters with last master on stream end
            for tx in g.master_waiters.drain(..) {
                let _ = tx.send(master.clone());
            }
            return Response::empty();
        }
        // Timeout: drain HTTP waiters with current playlist
        let playlist = self.inner.borrow().playlist.clone();
        let mut g = self.inner.borrow_mut();
        for (_, _, tx) in g.http_waiters.drain(..) {
            let _ = tx.send(playlist.clone());
        }
        // Drain master waiters on timeout
        if master.is_empty() {
            for tx in g.master_waiters.drain(..) {
                let _ = tx.send(String::new());
            }
        } else {
            for tx in g.master_waiters.drain(..) {
                let _ = tx.send(master.clone());
            }
        }
        drop(g);
        Response::empty()
    }
}

impl LlHlsDO {
    async fn configure_origin_route(&self, req: &Request) -> Result<()> {
        let stream_key = req.headers().get("X-Stream-Key")?.unwrap_or_default();
        if stream_key.is_empty() {
            return Err(Error::RustError("missing X-Stream-Key".into()));
        }
        let route = origin_route_from_headers(req.headers())?;
        let mut g = self.inner.borrow_mut();
        match &g.origin_route {
            Some(current) if current == &route && g.stream_key == stream_key => return Ok(()),
            Some(current) if route.route_version < current.route_version => {
                return Err(Error::RustError("stale origin route".into()));
            }
            Some(current) if route.route_version == current.route_version => {
                return Err(Error::RustError("conflicting origin route".into()));
            }
            Some(_) => {
                g.current_msn = 0;
                g.current_part = 0;
                g.playlist.clear();
                g.master_playlist.clear();
                for (_, _, tx) in g.http_waiters.drain(..) {
                    let _ = tx.send(String::new());
                }
                for tx in g.master_waiters.drain(..) {
                    let _ = tx.send(String::new());
                }
                g.origin_connected = false;
                g.should_clear = false;
            }
            None => {}
        }
        g.stream_key = stream_key.clone();
        g.origin_route = Some(route);
        drop(g);
        let _ = self.state.storage().put("stream_key", &stream_key).await;
        Ok(())
    }

    async fn handle_master_request(&self, req: &Request) -> Result<Response> {
        // 1. Fast path: already have master in memory
        {
            let g = self.inner.borrow();
            if !g.master_playlist.is_empty() {
                return master_playlist_response(&g.master_playlist);
            }
            if g.should_clear {
                return cors_error("Stream ended", 404);
            }
        }

        // 2. 503 overflow guard
        {
            let g = self.inner.borrow();
            if g.master_waiters.len() as u32 >= MAX_WAITERS_PER_SHARD {
                return Response::error("Shard full", 503);
            }
        }

        self.configure_origin_route(req).await?;

        // 4. Connect origin WS (if not already connected)
        if let Err(e) = self.ensure_origin_ws().await {
            console_log!("[LlHlsDO] ensure_origin_ws error: {:?}", e);
        }

        // 5. Set alarm timeout
        let _ = self.state.storage().set_alarm(VIEWER_TIMEOUT_MS).await;

        // 6. Block on oneshot
        let (tx, rx) = oneshot::channel::<String>();
        self.inner.borrow_mut().master_waiters.push(tx);

        match rx.await {
            Ok(playlist) => {
                if playlist.is_empty() {
                    cors_error("Master not available", 404)
                } else {
                    master_playlist_response(&playlist)
                }
            }
            Err(_) => {
                // Sender dropped (timeout) — return last known master or 404
                let pl = self.inner.borrow().master_playlist.clone();
                if pl.is_empty() {
                    cors_error("Master not available", 404)
                } else {
                    master_playlist_response(&pl)
                }
            }
        }
    }

    async fn ensure_initialized(&self) -> Result<()> {
        if self.inner.borrow().initialized {
            return Ok(());
        }
        let s = self.state.storage();
        let msn: u64 = s.get("msn").await.ok().flatten().unwrap_or(0);
        let part: u32 = s.get("part").await.ok().flatten().unwrap_or(0);
        let playlist: String = s.get("playlist").await.ok().flatten().unwrap_or_default();
        let mut g = self.inner.borrow_mut();
        g.current_msn = msn;
        g.current_part = part;
        g.playlist = playlist;
        g.initialized = true;
        Ok(())
    }

    /// Handle an incoming viewer WebSocket upgrade request.
    ///
    /// After upgrade, immediately sends the current playlist (if available)
    /// so the client can render right away — then stays connected for push updates.
    async fn handle_viewer_ws(&self, req: Request) -> Result<Response> {
        self.configure_origin_route(&req).await?;

        // Ensure origin WS is active so we receive future playlist updates.
        if let Err(e) = self.ensure_origin_ws().await {
            console_log!("[LlHlsDO] ensure_origin_ws error (viewer ws): {:?}", e);
        }

        // Create the viewer-facing WebSocket pair.
        let pair = WebSocketPair::new()?;
        let server_ws = pair.server;
        server_ws.accept()?;

        // Snapshot current state to send to the new viewer immediately.
        let (cur_msn, cur_part, playlist_now, should_clear) = {
            let g = self.inner.borrow();
            (
                g.current_msn,
                g.current_part,
                g.playlist.clone(),
                g.should_clear,
            )
        };

        // If stream has ended, tell the client immediately and don't register.
        if should_clear {
            if let Ok(json) = serde_json::to_string(&ViewerMsg::End) {
                let _ = server_ws.send_with_str(&json);
            }
            let _ = server_ws.close::<&str>(None, None);
            return Response::from_websocket(pair.client);
        }

        // Send current playlist immediately so the client doesn't have to wait.
        if !playlist_now.is_empty() {
            let msg = ViewerMsg::Part {
                msn: cur_msn,
                part: cur_part,
                playlist: &playlist_now,
            };
            if let Ok(json) = serde_json::to_string(&msg) {
                let _ = server_ws.send_with_str(&json);
            }
        }

        // Register this WebSocket for future push updates.
        self.inner.borrow_mut().viewer_ws.push(server_ws);

        Response::from_websocket(pair.client)
    }

    async fn ensure_origin_ws(&self) -> Result<()> {
        if self.inner.borrow().origin_connected {
            return Ok(());
        }
        let (stream_key, route) = {
            let g = self.inner.borrow();
            (
                g.stream_key.clone(),
                g.origin_route
                    .clone()
                    .ok_or_else(|| Error::RustError("origin route not set".into()))?,
            )
        };
        let wss_url = build_ws_url(&self.env, &stream_key, &route)?;
        self.inner.borrow_mut().origin_connected = true;
        let inner = self.inner.clone();

        wasm_bindgen_futures::spawn_local(async move {
            let inner_close = inner.clone();
            run_origin_ws(
                wss_url,
                move |msg, ws| {
                    match msg {
                        OriginMsg::Part {
                            msn,
                            part,
                            playlist,
                        } => {
                            if inner.borrow().origin_route.as_ref() != Some(&route) {
                                return true;
                            }
                            let mut g = inner.borrow_mut();
                            g.current_msn = msn;
                            g.current_part = part;
                            g.playlist = playlist.clone();

                            // Total viewers = HTTP waiters still pending + WS viewers.
                            let viewer_count = g.total_viewers();

                            // 1. Resolve HTTP waiters that are satisfied by this part.
                            let mut kept = Vec::new();
                            for (req_msn, req_part, tx) in g.http_waiters.drain(..) {
                                if satisfies(msn, part, req_msn, req_part) {
                                    let _ = tx.send(playlist.clone());
                                } else {
                                    kept.push((req_msn, req_part, tx));
                                }
                            }
                            g.http_waiters = kept;

                            // 2. Fan-out to all connected viewer WebSockets.
                            let viewer_msg = ViewerMsg::Part {
                                msn,
                                part,
                                playlist: &playlist,
                            };
                            g.fan_out_ws(&viewer_msg);

                            push_viewer_count(ws, viewer_count, msn, part);
                            false // keep running
                        }
                        OriginMsg::Simple { .. } => false, // LlHlsDO ignores Simple msgs
                        OriginMsg::Master { playlist } => {
                            if inner.borrow().origin_route.as_ref() != Some(&route) {
                                return true;
                            }
                            let mut g = inner.borrow_mut();
                            g.master_playlist = playlist.clone();
                            // Wake ALL master waiters (no selectivity — master is stateless)
                            for tx in g.master_waiters.drain(..) {
                                let _ = tx.send(playlist.clone());
                            }
                            false // keep running
                        }
                        OriginMsg::End => {
                            if inner.borrow().origin_route.as_ref() != Some(&route) {
                                return true;
                            }
                            let mut g = inner.borrow_mut();
                            let pl = g.playlist.clone();
                            let master_pl = g.master_playlist.clone();
                            // Drain HTTP waiters with last playlist.
                            for (_, _, tx) in g.http_waiters.drain(..) {
                                let _ = tx.send(pl.clone());
                            }
                            // Drain master waiters with last master (or empty)
                            for tx in g.master_waiters.drain(..) {
                                let _ = tx.send(master_pl.clone());
                            }
                            // Close all viewer WS connections with End message.
                            g.close_all_viewer_ws();
                            g.should_clear = true;
                            true // stop origin WS loop
                        }
                    }
                },
                move || {
                    inner_close.borrow_mut().origin_connected = false;
                },
            )
            .await;
        });

        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// SimpleDO — simple.m3u8
// ══════════════════════════════════════════════════════════════════════════════
struct SimpleInner {
    simple_playlist: String,
    simple_seq: u64,
    stream_key: String,
    origin_route: Option<OriginRoute>,
    /// HTTP blocking waiters
    http_waiters: Vec<oneshot::Sender<String>>,
    /// Connected viewer WebSockets for push delivery
    viewer_ws: Vec<WebSocket>,
    initialized: bool,
    origin_connected: bool,
    should_clear: bool,
}

impl Default for SimpleInner {
    fn default() -> Self {
        Self {
            simple_playlist: String::new(),
            simple_seq: 0,
            stream_key: String::new(),
            origin_route: None,
            http_waiters: Vec::new(),
            viewer_ws: Vec::new(),
            initialized: false,
            origin_connected: false,
            should_clear: false,
        }
    }
}

impl SimpleInner {
    fn total_viewers(&self) -> u32 {
        (self.http_waiters.len() + self.viewer_ws.len()) as u32
    }

    fn fan_out_ws(&mut self, msg: &ViewerMsg) {
        if self.viewer_ws.is_empty() {
            return;
        }
        if let Ok(json) = serde_json::to_string(msg) {
            self.viewer_ws.retain(|ws| ws.send_with_str(&json).is_ok());
        }
    }

    fn close_all_viewer_ws(&mut self) {
        let end_msg = serde_json::to_string(&ViewerMsg::End).unwrap_or_default();
        for ws in self.viewer_ws.drain(..) {
            let _ = ws.send_with_str(&end_msg);
            let _ = ws.close::<&str>(None, None);
        }
    }
}

#[durable_object]
pub struct SimpleDO {
    state: State,
    env: Env,
    inner: Rc<RefCell<SimpleInner>>,
}

impl DurableObject for SimpleDO {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            inner: Rc::new(RefCell::new(SimpleInner::default())),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.ensure_initialized().await?;

        // ── Route: Viewer WebSocket upgrade ──────────────────────────────────
        if req.headers().get("X-Viewer-WS")?.as_deref() == Some("1") {
            return self.handle_viewer_ws(req).await;
        }

        // ── Route: Blocking HTTP playlist request ─────────────────────────────
        {
            let g = self.inner.borrow();
            if g.http_waiters.len() as u32 >= MAX_WAITERS_PER_SHARD {
                return Response::error("Shard full", 503);
            }
        }

        self.configure_origin_route(&req).await?;

        let simple_now = self.inner.borrow().simple_playlist.clone();

        if self.inner.borrow().should_clear {
            let _ = self.state.storage().set_alarm(1).await;
            return if simple_now.is_empty() {
                cors_error("Stream not started yet", 404)
            } else {
                let wc = self.inner.borrow().total_viewers();
                simple_playlist_response(&simple_now, wc)
            };
        }

        if !simple_now.is_empty() {
            let wc = self.inner.borrow().total_viewers();
            return simple_playlist_response(&simple_now, wc);
        }

        if let Err(e) = self.ensure_origin_ws().await {
            console_log!("[SimpleDO] ensure_origin_ws error: {:?}", e);
        }

        let _ = self.state.storage().set_alarm(VIEWER_TIMEOUT_MS).await;

        let (tx, rx) = oneshot::channel::<String>();
        self.inner.borrow_mut().http_waiters.push(tx);

        match rx.await {
            Ok(playlist) => {
                let wc = self.inner.borrow().total_viewers();
                simple_playlist_response(&playlist, wc)
            }
            Err(_) => {
                let pl = self.inner.borrow().simple_playlist.clone();
                if pl.is_empty() {
                    cors_error("Stream not started yet", 404)
                } else {
                    let wc = self.inner.borrow().total_viewers();
                    simple_playlist_response(&pl, wc)
                }
            }
        }
    }

    async fn alarm(&self) -> Result<Response> {
        self.ensure_initialized().await?;
        let should_clear = self.inner.borrow().should_clear;
        if should_clear {
            let _ = self.state.storage().delete_all().await;
            let mut g = self.inner.borrow_mut();
            g.simple_playlist = String::new();
            g.should_clear = false;
            return Response::empty();
        }
        let pl = self.inner.borrow().simple_playlist.clone();
        let mut g = self.inner.borrow_mut();
        if pl.is_empty() {
            for tx in g.http_waiters.drain(..) {
                let _ = tx.send(String::new());
            }
        } else {
            for tx in g.http_waiters.drain(..) {
                let _ = tx.send(pl.clone());
            }
        }
        Response::empty()
    }
}

impl SimpleDO {
    async fn configure_origin_route(&self, req: &Request) -> Result<()> {
        let stream_key = req.headers().get("X-Stream-Key")?.unwrap_or_default();
        if stream_key.is_empty() {
            return Err(Error::RustError("missing X-Stream-Key".into()));
        }
        let route = origin_route_from_headers(req.headers())?;
        let mut g = self.inner.borrow_mut();
        match &g.origin_route {
            Some(current) if current == &route && g.stream_key == stream_key => return Ok(()),
            Some(current) if route.route_version < current.route_version => {
                return Err(Error::RustError("stale origin route".into()));
            }
            Some(current) if route.route_version == current.route_version => {
                return Err(Error::RustError("conflicting origin route".into()));
            }
            Some(_) => {
                g.simple_playlist.clear();
                g.simple_seq = 0;
                for tx in g.http_waiters.drain(..) {
                    let _ = tx.send(String::new());
                }
                g.origin_connected = false;
                g.should_clear = false;
            }
            None => {}
        }
        g.stream_key = stream_key.clone();
        g.origin_route = Some(route);
        drop(g);
        let _ = self.state.storage().put("stream_key", &stream_key).await;
        Ok(())
    }

    async fn ensure_initialized(&self) -> Result<()> {
        if self.inner.borrow().initialized {
            return Ok(());
        }
        let s = self.state.storage();
        let simple_playlist: String = s
            .get("simple_playlist")
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let simple_seq: u64 = s.get("simple_seq").await.ok().flatten().unwrap_or(0);
        let mut g = self.inner.borrow_mut();
        g.simple_playlist = simple_playlist;
        g.simple_seq = simple_seq;
        g.initialized = true;
        Ok(())
    }

    async fn handle_viewer_ws(&self, req: Request) -> Result<Response> {
        self.configure_origin_route(&req).await?;

        if let Err(e) = self.ensure_origin_ws().await {
            console_log!("[SimpleDO] ensure_origin_ws error (viewer ws): {:?}", e);
        }

        let pair = WebSocketPair::new()?;
        let server_ws = pair.server;
        server_ws.accept()?;

        let (playlist_now, seq_now, should_clear) = {
            let g = self.inner.borrow();
            (g.simple_playlist.clone(), g.simple_seq, g.should_clear)
        };

        if should_clear {
            if let Ok(json) = serde_json::to_string(&ViewerMsg::End) {
                let _ = server_ws.send_with_str(&json);
            }
            let _ = server_ws.close::<&str>(None, None);
            return Response::from_websocket(pair.client);
        }

        // Send current playlist immediately to the new viewer.
        if !playlist_now.is_empty() {
            let msg = ViewerMsg::Simple {
                seq: seq_now,
                playlist: &playlist_now,
            };
            if let Ok(json) = serde_json::to_string(&msg) {
                let _ = server_ws.send_with_str(&json);
            }
        }

        self.inner.borrow_mut().viewer_ws.push(server_ws);

        Response::from_websocket(pair.client)
    }

    async fn ensure_origin_ws(&self) -> Result<()> {
        if self.inner.borrow().origin_connected {
            return Ok(());
        }
        let (stream_key, route) = {
            let g = self.inner.borrow();
            (
                g.stream_key.clone(),
                g.origin_route
                    .clone()
                    .ok_or_else(|| Error::RustError("origin route not set".into()))?,
            )
        };
        let wss_url = build_ws_url(&self.env, &stream_key, &route)?;
        self.inner.borrow_mut().origin_connected = true;
        let inner = self.inner.clone();

        wasm_bindgen_futures::spawn_local(async move {
            let inner_close = inner.clone();
            run_origin_ws(
                wss_url,
                move |msg, ws| {
                    match msg {
                        OriginMsg::Simple { seq, playlist } => {
                            if inner.borrow().origin_route.as_ref() != Some(&route) {
                                return true;
                            }
                            let mut g = inner.borrow_mut();
                            if seq >= g.simple_seq {
                                g.simple_seq = seq;
                                g.simple_playlist = playlist.clone();

                                let viewer_count = g.total_viewers();

                                // 1. Resolve HTTP waiters.
                                for tx in g.http_waiters.drain(..) {
                                    let _ = tx.send(playlist.clone());
                                }

                                // 2. Fan-out to viewer WebSockets.
                                let viewer_msg = ViewerMsg::Simple {
                                    seq,
                                    playlist: &playlist,
                                };
                                g.fan_out_ws(&viewer_msg);

                                // Use seq as the "part" field for dedup at origin.
                                push_viewer_count(ws, viewer_count, 0, seq as u32);
                            }
                            false
                        }
                        OriginMsg::Part { .. } => false, // SimpleDO ignores Part msgs
                        OriginMsg::Master { .. } => false, // SimpleDO ignores Master msgs
                        OriginMsg::End => {
                            if inner.borrow().origin_route.as_ref() != Some(&route) {
                                return true;
                            }
                            let mut g = inner.borrow_mut();
                            let pl = g.simple_playlist.clone();
                            for tx in g.http_waiters.drain(..) {
                                let _ = tx.send(pl.clone());
                            }
                            g.close_all_viewer_ws();
                            g.should_clear = true;
                            true
                        }
                    }
                },
                move || {
                    inner_close.borrow_mut().origin_connected = false;
                },
            )
            .await;
        });

        Ok(())
    }
}

// ── Shared WS runtime ─────────────────────────────────────────────────────────

fn origin_route_from_headers(headers: &Headers) -> Result<OriginRoute> {
    let origin_base_url = headers
        .get(H_ORIGIN_BASE_URL)?
        .ok_or_else(|| Error::RustError("missing origin base url".into()))?;
    let node_id = headers
        .get(H_ORIGIN_NODE_ID)?
        .ok_or_else(|| Error::RustError("missing origin node id".into()))?;
    let stream_session_id = headers
        .get(H_ORIGIN_STREAM_SESSION_ID)?
        .ok_or_else(|| Error::RustError("missing origin stream session id".into()))?;
    let route_version = headers
        .get(H_ORIGIN_ROUTE_VERSION)?
        .ok_or_else(|| Error::RustError("missing origin route version".into()))?
        .parse()
        .map_err(|_| Error::RustError("invalid origin route version".into()))?;
    Ok(OriginRoute {
        origin_base_url: normalize_origin_base(&origin_base_url),
        node_id,
        stream_session_id,
        route_version,
    })
}

fn build_ws_url(env: &Env, stream_key: &str, route: &OriginRoute) -> Result<String> {
    if stream_key.is_empty() {
        return Err(Error::RustError("stream_key not set".into()));
    }
    let secret = env.var("ORIGIN_SECRET").ok().map(|v| v.to_string());
    let mut url = format!(
        "{}/internal/hls-ws/{}",
        route
            .origin_base_url
            .replace("https://", "wss://")
            .replace("http://", "ws://"),
        url_encode(&stream_key),
    );
    if let Some(secret) = secret.filter(|secret| !secret.is_empty()) {
        url.push_str("?origin_secret=");
        url.push_str(&url_encode(&secret));
    }
    Ok(url)
}

fn push_viewer_count(ws: &WebSocket, count: u32, msn: u64, part: u32) {
    if let Ok(json) = serde_json::to_string(&DoMsg::Viewers { count, msn, part }) {
        let _ = ws.send_with_str(&json);
    }
}

async fn run_origin_ws<F, C>(wss_url: String, mut on_msg: F, on_close: C)
where
    F: FnMut(OriginMsg, &WebSocket) -> bool,
    C: FnOnce(),
{
    match WebSocket::connect(wss_url.parse().unwrap()).await {
        Ok(ws) => {
            let mut events = match ws.events() {
                Ok(ev) => ev,
                Err(_) => {
                    on_close();
                    return;
                }
            };
            if ws.accept().is_err() {
                on_close();
                return;
            }

            while let Some(event) = events.next().await {
                match event {
                    Ok(WebsocketEvent::Message(msg)) => {
                        if let Some(text) = msg.text() {
                            if let Ok(m) = serde_json::from_str::<OriginMsg>(&text) {
                                if on_msg(m, &ws) {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(WebsocketEvent::Close(_)) | Err(_) => break,
                }
            }
            on_close();
        }
        Err(_) => on_close(),
    }
}

// ── Pure helpers ──────────────────────────────────────────────────────────────

fn satisfies(cur_msn: u64, cur_part: u32, req_msn: u64, req_part: u32) -> bool {
    cur_msn > req_msn || (cur_msn == req_msn && cur_part >= req_part)
}

fn ll_playlist_response(playlist: &str, waiter_count: u32) -> Result<Response> {
    let h = Headers::new();
    let _ = h.set("Content-Type", "application/vnd.apple.mpegurl");
    let _ = h.set("Cache-Control", "no-store");
    let _ = h.set("Access-Control-Allow-Origin", "*");
    let _ = h.set("X-Waiter-Count", &waiter_count.to_string());
    Response::ok(playlist).map(|r| r.with_headers(h))
}

fn simple_playlist_response(playlist: &str, viewer_count: u32) -> Result<Response> {
    let h = Headers::new();
    let _ = h.set("Content-Type", "application/vnd.apple.mpegurl");
    let _ = h.set(
        "Cache-Control",
        "public, max-age=1, stale-while-revalidate=1",
    );
    let _ = h.set("Access-Control-Allow-Origin", "*");
    let _ = h.set("X-Viewer-Count", &viewer_count.to_string());
    Response::ok(playlist).map(|r| r.with_headers(h))
}

fn master_playlist_response(playlist: &str) -> Result<Response> {
    let h = Headers::new();
    let _ = h.set("Content-Type", "application/vnd.apple.mpegurl");
    let _ = h.set("Cache-Control", "no-store");
    let _ = h.set("Access-Control-Allow-Origin", "*");
    Response::ok(playlist).map(|r| r.with_headers(h))
}

/// Parse tokenized playback paths handled by this Worker.
///
/// Playlists are relayed through DO. Media objects are intentionally rejected
/// because init/segment/part delivery is owned by CDN/origin routing outside
/// this Worker.
fn parse_playlist_path(path: &str) -> Option<ParsedRequest> {
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match segs.as_slice() {
        ["hls", "t", token, "live", stream_id, filename] => {
            let playlist_type = playlist_type(filename)?;
            Some(ParsedRequest {
                token: (*token).to_string(),
                stream_id: (*stream_id).to_string(),
                stream_key: (*stream_id).to_string(),
                playlist_type,
            })
        }
        ["hls", "t", token, "live", stream_id, rendition, filename] => {
            let playlist_type = playlist_type(filename)?;
            let stream_key = if *rendition == "source" || *rendition == "original" {
                (*stream_id).to_string()
            } else {
                format!("{stream_id}:{rendition}")
            };
            Some(ParsedRequest {
                token: (*token).to_string(),
                stream_id: (*stream_id).to_string(),
                stream_key,
                playlist_type,
            })
        }
        ["hls", "t", token, "live", stream_id, ..] => Some(ParsedRequest {
            token: (*token).to_string(),
            stream_id: (*stream_id).to_string(),
            stream_key: (*stream_id).to_string(),
            playlist_type: "media",
        }),
        _ => None,
    }
}

fn playlist_type(filename: &str) -> Option<&'static str> {
    match filename {
        "master.m3u8" => Some("master"),
        "playlist.m3u8" => Some("llhls"),
        "simple.m3u8" => Some("simple"),
        "playlist-ws" => Some("llhls-ws"),
        "simple-ws" => Some("simple-ws"),
        _ => None,
    }
}

fn url_encode(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

fn djb2_hash(s: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in s.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

fn get_max_shards(env: &Env) -> u32 {
    env.var("MAX_SHARDS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(250)
}
