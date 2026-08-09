# Clash subscription Worker

This companion Worker serves the existing `clash.w0x7ce.eu` subscription paths while keeping credentials in Cloudflare secrets.

Required secrets:

- `SECRET_TOKEN`
- `PAGE_PASSWORD`
- `NODES_JSON`
- `CLOUDFLARE_UUID`

`CLOUDFLARE_UUID` is normalized before use and must be a canonical version-4 UUID. Generated Cloudflare nodes use `edgetunnel.w0x7ce.eu`, the dedicated `/tunnel` path, certificate verification, and TCP-only mode. To use a scanned Cloudflare address, change only the node `server`; keep SNI/servername, Host, and path unchanged.

Deploy with:

```powershell
npx wrangler deploy --config workers/clash-sub/wrangler.toml
```
