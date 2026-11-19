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
  netctrl.js        PS4 13.00 kernel exploit (NetControl UAF)
  ps4/ ps5/         Per-console implementations
payloads/
  ps4/payload.bin   GoldHEN for PS4
  ps5/kexp.bin      Kernel exploit for PS5
  ps5/elfldr.elf    ELF loader for PS5
tools/
  host.py           Optional local HTTPS server (uses localhost.pem)
```

The engine was kept functionally unchanged; only asset paths were updated for the new layout, plus one addition: `engine/netctrl.js` ports the NetControl UAF kernel exploit to wobkot's own WebKit/userland entry so PS4 13.00 is supported without bundling any external WebKit chain. The kernel offsets for 13.00 are in `engine/ps4/impl.js`.

## Payloads

The binary payloads are included in the repository so GitHub Pages can serve them directly to the launcher:

- **PS4:** `payloads/ps4/payload.bin` (GoldHEN)
- **PS5:** `payloads/ps5/kexp.bin` and `payloads/ps5/elfldr.elf`

Only your console's files are used. The launcher page shows the exact paths.

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
