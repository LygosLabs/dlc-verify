# The web page

`web/` is a static page that runs dlc-verify in the browser, through the
[WebAssembly module](wasm.md). Messages never leave the page: there is no server code, and the
page's Content-Security-Policy lets it load only its own files.

It does what the command-line tool does:

- **Verify**: paste a bundle or an offer in hex, or open or drop a file. Or give the offer,
  accept and sign separately. The page shows the verdict, the contract, every check, and who each
  CET and the refund pay, with the text report to copy and the JSON report to download.
- **Expected terms**: choose a [profile](profiles.md) and paste its terms, or paste a
  [policy](policy.md), to check that the messages are the contract you agreed to.
- **Close the contract**: complete the CET for an oracle attestation, or the refund, as
  [`settle` and `refund`](settle.md) do. Copy or download the signed transaction and broadcast it
  yourself.

The page passes the browser's clock as `now`, and says so. Untick the clock box to verify without
one: the maturity checks then only warn.

## Run it locally

```sh
tools/build-wasm.sh                  # builds web/pkg and runs the checks below
python3 -m http.server -d web 8000   # any static server; open http://localhost:8000
```

Opening `web/index.html` from disk does not work: browsers do not load modules from `file:` URLs.

## Files

| File | What it does |
|---|---|
| `index.html` | The page and its Content-Security-Policy |
| `style.css` | Styles, light and dark |
| `app.js` | Reads the form and shows the results. It writes what a message says as text, never as HTML |
| `engine.js` | Loads the module, and loads it again after a call traps (see [wasm.md](wasm.md)) |
| `view.js` | Pure helpers: requests from the form, reports to text |
| `pkg/` | The module, built by `tools/build-wasm.sh`; not committed |

`tools/web.test.mjs` tests `view.js`. It also runs every fixture through `engine.js` and the
built module, and checks that `index.html` has every element `app.js` uses. `tools/build-wasm.sh`
runs it, and you can run it alone with `node --test tools/web.test.mjs`.

## Hosting

Any static host serves `web/` once `web/pkg` is built. The CI's `wasm` job uploads the whole
directory as the `dlc-verify-web` artifact, and each release has it as
`dlc-verify-web-vX.Y.Z.tar.gz`. The host should:

- serve `.wasm` as `application/wasm`; the page still works without it, a little slower;
- send `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or
  `frame-ancestors 'none'`, which a `<meta>` policy cannot set) and a strict `Referrer-Policy`.

### Vercel

`vercel.json` serves `web/` with those headers. Vercel's build machines cannot build the module,
so Vercel does not build from git (`git.deploymentEnabled` is off). Instead, the `deploy` job in
`.github/workflows/rust.yml` deploys every push to `main`: it takes the page the `wasm` job built
and tested, then runs `vercel build` and `vercel deploy --prebuilt --prod`. It needs three
repository secrets, and skips the deploy without them:

| Secret | Value |
|---|---|
| `VERCEL_TOKEN` | A Vercel access token that can deploy the project |
| `VERCEL_ORG_ID` | The team id: `orgId` in `.vercel/project.json` after `vercel link` |
| `VERCEL_PROJECT_ID` | `projectId` in the same file |

To deploy by hand, build first: `tools/build-wasm.sh`, then `vercel build --prod` and
`vercel deploy --prebuilt --prod`. `vercel build` stops with an error if `web/pkg` is missing.
