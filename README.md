# dotfiles

## pi extensions

`.pi/agent/extensions/web-search` — websearch/webfetch tools for pi (port of opencode's tools).

Install on a new machine:

```bash
git clone https://github.com/infdespcmg/.dotfiles.git ~/.dotfiles
mkdir -p ~/.pi/agent/extensions
ln -s ~/.dotfiles/.pi/agent/extensions/web-search ~/.pi/agent/extensions/web-search
cd ~/.pi/agent/extensions/web-search && npm install --omit=dev
```

Optional env: `PI_WEBSEARCH_PROVIDER` (`exa`|`parallel`), `EXA_API_KEY`, `PARALLEL_API_KEY`.

Provider choice order: `PI_WEBSEARCH_PROVIDER` → `PARALLEL_API_KEY` present → `exa`.
`EXA_API_KEY` goes in the `x-api-key` header, never in the URL.
`webfetch` refuses private/loopback hosts (SSRF guard) and non-text content types.
