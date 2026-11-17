# wobkot — static site

A static-site build of [ufm42/wobkot](https://github.com/ufm42/wobkot): a userland for PS4 / PS5 WebKit. The page is plain HTML/CSS/JS — there is no backend, and it is published with GitHub Pages.

Live site: **https://slopkit-ps4.github.io/wobkot/**

## Layout

```
index.html          Landing page, device info, launcher, console panel
assets/
  styles.css        Dark responsive theme
  app.js            UI logic and Launch button
engine/             Exploit engine (formerly src/)
  main.js           Loader exposed as window.wobkot.start()
  worker.js         Web Worker entry point
  ps4/ ps5/         Per-console implementations
payloads/
  ps4/payload.bin   Add before launching on PS4
  ps5/kexp.bin      Add before launching on PS5
  ps5/elfldr.elf    Add before launching on PS5
tools/
  host.py           Optional local HTTPS server (uses localhost.pem)
```

The engine was kept functionally unchanged; only asset paths were updated for the new layout.

## Payloads

The binary payloads are **not included** in this repository. Add the files for your console to the `payloads/` folders above before pressing Launch. The launcher page shows the exact paths.

## Hosting

The site is served from the `main` branch root via GitHub Pages. Because every path is relative, it works at both `https://<user>.github.io/wobkot/` and a custom domain.

To preview locally:

```sh
python3 -m http.server 8000
# open http://localhost:8000
```

The original `tools/host.py` serves the same files over HTTPS on port 443 with the bundled `localhost.pem`, matching the upstream project's workflow.

## Credits and references

Based on [ufm42/wobkot](https://github.com/ufm42/wobkot), MIT licensed. See [LICENSE.txt](LICENSE.txt) and the upstream README for the full credits and exploit references.
