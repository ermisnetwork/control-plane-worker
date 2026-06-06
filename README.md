# Control Plane Worker

The default `wrangler.toml` deployment validates playback JWTs. The separate
`wrangler.no-auth.toml` deployment exposes a public playlist relay without
checking client authorization.

The no-auth deployment still uses `ORIGIN_SECRET` for the Worker-to-node
WebSocket. It does not proxy init segments, parts, media segments, or keys.
Those URLs remain owned by the origin/CDN.

## Deploy the no-auth relay

Review `ORIGIN_BASE_URL` in `wrangler.no-auth.toml`, then configure the node
origin secret:

```bash
npx wrangler secret put ORIGIN_SECRET --config wrangler.no-auth.toml
npx wrangler deploy --config wrangler.no-auth.toml
```

The configured node must have the Durable Object playlist relay enabled and
must accept the same origin secret.

## Public routes

No token or `Authorization` header is required:

```text
/hls/live/{stream_id}/master.m3u8
/hls/live/{stream_id}/playlist.m3u8
/hls/live/{stream_id}/{rendition}/playlist.m3u8
/hls/live/{stream_id}/simple.m3u8
/hls/live/{stream_id}/{rendition}/simple.m3u8
```

`source` and `original` map to the base stream key. Other rendition names map
to `{stream_id}:{rendition}`.

## Test

Start publishing the stream first. Then set:

```bash
export WORKER_URL=https://test-control-plane-worker-no-auth.<account>.workers.dev
export STREAM_ID=019e9b4e-eb18-7682-9319-2a588508bd82
```

Check the master and source playlists:

```bash
curl -i "$WORKER_URL/hls/live/$STREAM_ID/master.m3u8"
curl -i "$WORKER_URL/hls/live/$STREAM_ID/playlist.m3u8"
```

The expected result is HTTP `200`, content type
`application/vnd.apple.mpegurl`, and no JWT in the URL.

Test LL-HLS blocking reload:

```bash
PLAYLIST="$WORKER_URL/hls/live/$STREAM_ID/playlist.m3u8"
BODY="$(curl -fsS "$PLAYLIST")"
MSN="$(printf '%s\n' "$BODY" | sed -n 's/^#EXT-X-MEDIA-SEQUENCE://p')"
curl -i --max-time 8 "$PLAYLIST?_HLS_msn=$((MSN + 4))&_HLS_part=0"
```

For native Safari, open:

```text
https://test-control-plane-worker-no-auth.<account>.workers.dev/hls/live/019e9b4e-eb18-7682-9319-2a588508bd82/master.m3u8
```

This relay only forwards playlists. Safari still fetches the absolute
init/part/segment URLs emitted by the node, so those URLs must be public HTTPS
and Safari-compatible.
