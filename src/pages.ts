// Server-rendered HTML pages: the landing page, the human share page, and the
// invalid-room page. Zero external requests — system fonts, inline CSS and JS —
// because a private-room service should not phone home to a font CDN.
//
// Visual language: a dark instrument panel. Halftone dot screen and film grain,
// hairline registration marks, tiny tracked mono labels, bracketed panels, and
// warm paper "passes" that carry the room id. One vermillion accent, used sparingly.
// Every readout on these pages is either real (clock, health, the room's own
// settings) or a true statement about the service — nothing decorative claims data.

const GITHUB_URL = "https://github.com/ianzepp/fleeting-chat";

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Brand mark: a chat bubble whose reply dots fade out. Shared by the header and favicon. */
const MARK_SVG = `<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#ff5a2c"/><path d="M9.5 8.5h13a3.5 3.5 0 0 1 3.5 3.5v6a3.5 3.5 0 0 1-3.5 3.5H17l-4.2 3.3a.6.6 0 0 1-1-.47V21.5h-2.3A3.5 3.5 0 0 1 6 18v-6a3.5 3.5 0 0 1 3.5-3.5z" fill="#0a0c0f"/><circle cx="11.5" cy="15" r="1.5" fill="#ff5a2c"/><circle cx="16" cy="15" r="1.5" fill="#ff5a2c" opacity=".6"/><circle cx="20.5" cy="15" r="1.5" fill="#ff5a2c" opacity=".3"/></svg>`;

export const FAVICON_SVG = MARK_SVG.replace(' aria-hidden="true"', "");

// Film grain and paper fibre as inline SVG noise (no extra requests).
const NOISE = (rgb: string, alpha: string) =>
  `url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='220' height='220'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 ${rgb} 0 0 0 0 ${rgb} 0 0 0 0 ${rgb} 0 0 0 ${alpha} 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>")`;

/** Tokens, background, instrument frame, header, brackets, buttons, and the paper pass. */
const BASE_CSS = `
    :root {
      color-scheme: dark light;
      --bg: #0a0c0f;
      --ink: #ebe8e0;
      --ink-soft: #aeaba2;
      --ink-faint: #868481;
      --line: rgba(235, 232, 224, 0.13);
      --line-strong: rgba(235, 232, 224, 0.3);
      --panel: rgba(235, 232, 224, 0.03);
      --accent: #ff5a2c;
      --on-accent: #0a0c0f;
      --ok: #4cc795;
      --danger: #ff6a5c;
      --glow-a: rgba(64, 112, 184, 0.3);
      --glow-b: rgba(255, 90, 44, 0.11);
      --dot: rgba(235, 232, 224, 0.075);
      --grain: ${NOISE("1", ".5")};
      --grain-opacity: 0.1;
      --term-bg: #0d1014;
      --paper: #e9e5d9;
      --paper-ink: #18150f;
      --paper-soft: #5e594c;
      --paper-grain: ${NOISE("0", ".22")};
      --sans: ui-sans-serif, -apple-system, "SF Pro Display", "Segoe UI", system-ui, sans-serif;
      --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #e8e5db;
        --ink: #15130f;
        --ink-soft: #46423a;
        --ink-faint: #6a665c;
        --line: rgba(21, 19, 15, 0.16);
        --line-strong: rgba(21, 19, 15, 0.36);
        --panel: rgba(255, 255, 255, 0.34);
        --accent: #c8330c;
        --on-accent: #fff7f2;
        --ok: #17794f;
        --danger: #b3261e;
        --glow-a: rgba(64, 112, 184, 0.16);
        --glow-b: rgba(255, 90, 44, 0.12);
        --dot: rgba(21, 19, 15, 0.1);
        --grain: ${NOISE("0", ".5")};
        --grain-opacity: 0.09;
        --paper: #f6f3ea;
      }
    }
    * { box-sizing: border-box; }
    html { -webkit-text-size-adjust: 100%; }
    body {
      margin: 0;
      min-height: 100dvh;
      padding-bottom: 3rem;
      font-family: var(--sans);
      color: var(--ink);
      background: var(--bg);
      -webkit-font-smoothing: antialiased;
      line-height: 1.5;
      overflow-x: hidden;
    }
    a { color: inherit; text-decoration: none; }
    a:focus-visible, button:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
    code { font-family: var(--mono); font-size: 0.9em; }
    [hidden] { display: none !important; }
    ::selection { background: var(--accent); color: var(--on-accent); }

    /* Scene: cold light from above, a warm spill below, and a halftone dot screen. */
    .bg {
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background:
        radial-gradient(52rem 30rem at 72% -8%, var(--glow-a), transparent 70%),
        radial-gradient(40rem 26rem at 0% 104%, var(--glow-b), transparent 70%);
    }
    .bg::after {
      content: ""; position: absolute; inset: 0;
      background-image: radial-gradient(circle, var(--dot) 0.9px, transparent 1.4px);
      background-size: 6px 6px;
      -webkit-mask-image: linear-gradient(to bottom, #000 35%, rgba(0, 0, 0, 0.45));
      mask-image: linear-gradient(to bottom, #000 35%, rgba(0, 0, 0, 0.45));
    }
    .grain {
      position: fixed; inset: -20%; z-index: 4; pointer-events: none;
      background-image: var(--grain); background-size: 220px 220px;
      opacity: var(--grain-opacity);
      animation: grain 1s steps(1) infinite;
    }
    @keyframes grain {
      0% { transform: translate(0, 0); } 10% { transform: translate(-4%, 3%); }
      20% { transform: translate(3%, -5%); } 30% { transform: translate(-6%, 2%); }
      40% { transform: translate(5%, 5%); } 50% { transform: translate(-3%, -4%); }
      60% { transform: translate(6%, 1%); } 70% { transform: translate(-5%, 6%); }
      80% { transform: translate(2%, -6%); } 90% { transform: translate(-2%, 4%); }
    }

    /* Instrument frame: registration marks, tick ruler, corner labels, ticker. */
    .hud { position: fixed; inset: 0; z-index: 5; pointer-events: none; color: var(--ink-faint); }
    .hud .c {
      position: absolute; width: 15px; height: 15px;
      background:
        linear-gradient(currentColor, currentColor) center / 100% 1px no-repeat,
        linear-gradient(currentColor, currentColor) center / 1px 100% no-repeat;
    }
    .hud .tl { top: 10px; left: 10px; } .hud .tr { top: 10px; right: 10px; }
    .hud .bl { bottom: calc(1.9rem + 10px); left: 10px; } .hud .br { bottom: calc(1.9rem + 10px); right: 10px; }
    .hud .lbl { position: absolute; top: 14px; font: 500 0.62rem/1 var(--mono); letter-spacing: 0.16em; text-transform: uppercase; }
    .hud .l1 { left: 34px; } .hud .l2 { right: 34px; }
    .hud .ruler {
      position: absolute; left: 12px; top: 6rem; bottom: 4.5rem; width: 12px; opacity: 0.55;
      background:
        repeating-linear-gradient(to bottom, currentColor 0 1px, transparent 1px 50px) left / 12px 100% no-repeat,
        repeating-linear-gradient(to bottom, currentColor 0 1px, transparent 1px 10px) left / 6px 100% no-repeat;
    }
    .ticker {
      position: absolute; left: 0; right: 0; bottom: 0; height: 1.9rem; overflow: hidden;
      display: flex; align-items: center;
      border-top: 1px solid var(--line);
      background: color-mix(in srgb, var(--bg) 84%, transparent);
      -webkit-backdrop-filter: blur(6px); backdrop-filter: blur(6px);
      font: 500 0.62rem/1 var(--mono); letter-spacing: 0.16em; text-transform: uppercase; white-space: nowrap;
    }
    .ticker-track { display: flex; width: max-content; animation: tick 70s linear infinite; }
    .ticker-group { display: flex; align-items: center; flex-shrink: 0; }
    .ticker-group > span { padding: 0 1.1rem; }
    .ticker-group > i { width: 4px; height: 4px; background: var(--accent); flex-shrink: 0; }
    .ticker .on { color: var(--ok); } .ticker .off { color: var(--danger); }
    @keyframes tick { to { transform: translateX(-50%); } }

    .site-header, .wrap { position: relative; z-index: 2; width: min(76rem, 100%); margin: 0 auto; padding-left: clamp(1.1rem, 5vw, 3rem); padding-right: clamp(1.1rem, 5vw, 3rem); }
    .site-header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding-top: 2.6rem; }
    .brand { display: inline-flex; align-items: center; gap: 0.7rem; font: 600 0.78rem/1 var(--mono); letter-spacing: 0.2em; text-transform: uppercase; }
    .brand svg { width: 1.55rem; height: 1.55rem; flex-shrink: 0; }
    .site-nav { display: flex; gap: 0.25rem; font: 500 0.68rem/1 var(--mono); letter-spacing: 0.16em; text-transform: uppercase; color: var(--ink-soft); }
    .site-nav a { padding: 0.55rem 0.7rem; white-space: nowrap; border: 1px solid transparent; transition: border-color 140ms ease, color 140ms ease; }
    .site-nav a:hover { border-color: var(--line-strong); color: var(--ink); }

    .site-footer { position: relative; z-index: 2; width: min(76rem, 100%); margin: 0 auto; padding: 0 clamp(1.1rem, 5vw, 3rem) 2.5rem; }
    .site-footer .inner { display: grid; grid-template-columns: minmax(0, 14rem) minmax(0, 1fr); gap: 1rem clamp(1.5rem, 5vw, 4rem); padding-top: 1.6rem; border-top: 1px solid var(--line); }
    .site-footer h2 { margin: 0; font: 500 0.68rem/1.4 var(--mono); letter-spacing: 0.18em; text-transform: uppercase; color: var(--ink-faint); }
    .site-footer .links { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.9rem; font: 500 0.66rem/1 var(--mono); letter-spacing: 0.14em; text-transform: uppercase; }
    .site-footer .links a { padding: 0.55rem 0.7rem; border: 1px solid var(--line-strong); transition: border-color 140ms ease, color 140ms ease, background 140ms ease; }
    .site-footer .links a:hover { border-color: var(--ink); background: var(--panel); }
    .site-footer p { margin: 0; max-width: 46rem; font-size: 0.82rem; line-height: 1.65; color: var(--ink-faint); }
    .site-footer p + p { margin-top: 0.6rem; }
    @media (max-width: 48rem) { .site-footer .inner { grid-template-columns: minmax(0, 1fr); } }
    .wrap { padding-top: clamp(1.75rem, 5vw, 3.5rem); padding-bottom: 3rem; }

    /* Bracketed panel: faint tint, hairline edge, bright corner brackets. */
    .brackets {
      --bk: var(--ink-soft);
      position: relative;
      border: 1px solid var(--line);
      background:
        linear-gradient(var(--bk), var(--bk)) top left / 14px 1px no-repeat,
        linear-gradient(var(--bk), var(--bk)) top left / 1px 14px no-repeat,
        linear-gradient(var(--bk), var(--bk)) top right / 14px 1px no-repeat,
        linear-gradient(var(--bk), var(--bk)) top right / 1px 14px no-repeat,
        linear-gradient(var(--bk), var(--bk)) bottom left / 14px 1px no-repeat,
        linear-gradient(var(--bk), var(--bk)) bottom left / 1px 14px no-repeat,
        linear-gradient(var(--bk), var(--bk)) bottom right / 14px 1px no-repeat,
        linear-gradient(var(--bk), var(--bk)) bottom right / 1px 14px no-repeat,
        var(--panel);
      background-origin: border-box;
    }

    .kicker { display: flex; align-items: center; gap: 0.6rem; margin: 0; font: 500 0.68rem/1.4 var(--mono); letter-spacing: 0.18em; text-transform: uppercase; color: var(--ink-faint); }
    .kicker .sq { width: 7px; height: 7px; background: var(--accent); animation: blink 1.4s steps(1) infinite; flex-shrink: 0; }
    @keyframes blink { 50% { opacity: 0; } }
    .rule { position: relative; height: 1px; margin: 1.5rem 0; background: var(--line); transform-origin: left; animation: draw 1s 0.15s cubic-bezier(0.2, 0.7, 0.2, 1) both; }
    .rule::before { content: ""; position: absolute; left: 0; top: -1px; width: 3.5rem; height: 3px; background: var(--accent); }
    @keyframes draw { from { transform: scaleX(0); } }

    .btn {
      font: 600 0.72rem/1 var(--mono);
      letter-spacing: 0.14em;
      text-transform: uppercase;
      display: inline-flex; align-items: center; justify-content: center; gap: 0.6rem;
      padding: 0.95rem 1.15rem;
      border: 0;
      cursor: pointer;
      clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px));
      transition: background 140ms ease, color 140ms ease, transform 140ms ease, opacity 140ms ease;
    }
    .btn:active { transform: translateY(1px); }
    .btn:disabled { opacity: 0.35; cursor: not-allowed; transform: none; }
    .btn-accent { background: var(--accent); color: var(--on-accent); }
    .btn-accent:not(:disabled):hover { background: color-mix(in srgb, var(--accent) 82%, #fff); }
    .btn-ghost { background: transparent; color: inherit; box-shadow: inset 0 0 0 1px var(--line-strong); }
    .btn-ghost:not(:disabled):hover { box-shadow: inset 0 0 0 1px currentColor; }
    .btn.done { background: var(--ok); color: #06140d; box-shadow: none; }

    .spec { list-style: none; margin: 0; padding: 0; counter-reset: spec; }
    .spec li { display: grid; grid-template-columns: 2.2rem 1fr; gap: 0 0.75rem; padding: 1rem 0; border-top: 1px solid var(--line); counter-increment: spec; }
    .spec li:last-child { border-bottom: 1px solid var(--line); }
    .spec li::before { content: "0" counter(spec); font: 600 0.72rem/1.9 var(--mono); letter-spacing: 0.1em; color: var(--accent); }
    .spec h3 { margin: 0 0 0.2rem; font-size: 0.98rem; font-weight: 600; letter-spacing: -0.01em; }
    .spec p, .spec span.t { margin: 0; font-size: 0.88rem; color: var(--ink-soft); line-height: 1.55; }
    .spec code { color: var(--ink); }

    /* Warm paper pass: the room id lives here. Perforated, tilted, slightly grainy. */
    .pass-wrap { position: relative; }
    .pass { --tilt: -0.7deg; color: var(--paper-ink); transform: rotate(var(--tilt)); transform-origin: 50% 0; filter: drop-shadow(0 26px 20px rgba(0, 0, 0, 0.42)); }
    .pass-main, .pass-stub { position: relative; background-color: var(--paper); background-image: var(--paper-grain); }
    .pass-main {
      padding: 1.05rem 1.3rem 1.35rem;
      -webkit-mask: radial-gradient(circle 0.6rem at 0 100%, transparent 98%, #000) left / 50.5% 100% no-repeat, radial-gradient(circle 0.6rem at 100% 100%, transparent 98%, #000) right / 50.5% 100% no-repeat;
      mask: radial-gradient(circle 0.6rem at 0 100%, transparent 98%, #000) left / 50.5% 100% no-repeat, radial-gradient(circle 0.6rem at 100% 100%, transparent 98%, #000) right / 50.5% 100% no-repeat;
    }
    .pass-stub {
      padding: 1.1rem 1.3rem 1.3rem;
      -webkit-mask: radial-gradient(circle 0.6rem at 0 0, transparent 98%, #000) left / 50.5% 100% no-repeat, radial-gradient(circle 0.6rem at 100% 0, transparent 98%, #000) right / 50.5% 100% no-repeat;
      mask: radial-gradient(circle 0.6rem at 0 0, transparent 98%, #000) left / 50.5% 100% no-repeat, radial-gradient(circle 0.6rem at 100% 0, transparent 98%, #000) right / 50.5% 100% no-repeat;
    }
    .pass-stub::before { content: ""; position: absolute; top: 0; left: 0.9rem; right: 0.9rem; border-top: 1.5px dashed rgba(24, 21, 15, 0.32); }
    .pass-top { display: flex; justify-content: space-between; gap: 1rem; margin-bottom: 0.85rem; padding-bottom: 0.55rem; border-bottom: 1px solid rgba(24, 21, 15, 0.2); font: 500 0.6rem/1.2 var(--mono); letter-spacing: 0.16em; text-transform: uppercase; color: var(--paper-soft); }
    .pass-title { margin: 0 0 0.35rem; font: 600 0.9rem/1.3 var(--sans); letter-spacing: -0.01em; }
    .channel { font: 600 clamp(1.75rem, 6.4vw, 2.5rem)/1.15 var(--mono); letter-spacing: 0.05em; color: var(--paper-ink); word-break: break-all; font-variant-numeric: tabular-nums; }
    .barcode { display: block; width: 100%; height: 2rem; margin-top: 0.7rem; fill: var(--paper-ink); }
    .fields { display: grid; gap: 0.38rem; margin: 0.95rem 0 0; }
    .fields .row { display: flex; align-items: baseline; gap: 0.5rem; font: 500 0.64rem/1.3 var(--mono); letter-spacing: 0.12em; text-transform: uppercase; }
    .fields dt { color: var(--paper-soft); }
    .fields dd { margin: 0; font-weight: 700; color: var(--paper-ink); }
    .fields .lead { flex: 1; min-width: 0.5rem; border-bottom: 1px dotted rgba(24, 21, 15, 0.45); transform: translateY(-0.2em); }
    .pass .btn-accent { background: var(--paper-ink); color: var(--paper); }
    .pass .btn-accent:not(:disabled):hover { background: #3a352b; }
    .pass .btn-ghost { color: var(--paper-ink); box-shadow: inset 0 0 0 1px rgba(24, 21, 15, 0.45); }
    .pass .btn-ghost:not(:disabled):hover { box-shadow: inset 0 0 0 1px var(--paper-ink); }

    @media (max-width: 48rem) {
      .hud .ruler { display: none; }
      .hud .l1 { left: 30px; } .hud .l2 { right: 30px; }
      .site-nav a { padding: 0.55rem 0.45rem; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation: none !important; transition: none !important; }
    }
`;

/** Shared by every page: UTC clock readout and the (decorative, deterministic) barcode renderer. */
const HUD_SCRIPT = `
    (function () {
      function p(n) { return n < 10 ? "0" + n : String(n); }
      var clock = document.getElementById("hudClock");
      if (clock) {
        var tick = function () {
          var d = new Date();
          clock.textContent = "UTC " + p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + ":" + p(d.getUTCSeconds());
        };
        tick();
        setInterval(tick, 1000);
      }
      window.fcBarcode = function (svg, id) {
        var digits = String(id).replace(/\\D/g, ""), x = 0, out = "";
        function bar(w) { out += '<rect x="' + x + '" y="0" width="' + w + '" height="30"/>'; x += w; }
        bar(1); x += 1; bar(1); x += 2;
        for (var i = 0; i < digits.length; i++) {
          var d = Number(digits[i]);
          bar(1 + (d % 3)); x += 1 + ((d * 3 + 1) % 2);
          bar(1 + ((d * 5 + 2) % 3)); x += 1 + ((d + i) % 3);
        }
        x += 1; bar(1); x += 1; bar(2);
        svg.setAttribute("viewBox", "0 0 " + x + " 30");
        svg.setAttribute("preserveAspectRatio", "none");
        svg.innerHTML = out;
      };
    })();
`;

// Ticker lines are true statements about the service (see README), not telemetry.
const TICKER_FACTS = [
  "Plain HTTP",
  "Auth · ED25519 seat keys",
  "Seats 2–8",
  "Lifetime 1h–30d",
  "At rest · AES-256-GCM by default",
  "End-to-end · none",
  "Rooms deleted on expiry",
  "No accounts",
  "No installs",
];

function ticker(extra: string): string {
  const items = [...(extra ? [extra] : []), ...TICKER_FACTS].map((t) => (t.startsWith("<") ? t : `<span>${t}</span>`));
  const group = `<div class="ticker-group">${items.join("<i></i>")}<i></i></div>`;
  return `<div class="ticker" aria-hidden="true"><div class="ticker-track">${group}${group}</div></div>`;
}

interface PageParts {
  head: string;
  css: string;
  body: string;
  /** Top-left instrument label. */
  label: string;
  /** Raw HTML for one extra ticker item (e.g. a live health readout). */
  tickerExtra?: string;
  /** Page script, run after the shared HUD script. */
  script?: string;
}

function shell(page: PageParts): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <meta name="theme-color" content="#0a0c0f" media="(prefers-color-scheme: dark)"/>
  <meta name="theme-color" content="#e8e5db" media="(prefers-color-scheme: light)"/>
  <link rel="icon" href="/favicon.svg" type="image/svg+xml"/>
${page.head}
  <style>
${BASE_CSS}
${page.css}
  </style>
</head>
<body>
  <div class="bg" aria-hidden="true"></div>
  <div class="grain" aria-hidden="true"></div>
  <div class="hud" aria-hidden="true">
    <i class="c tl"></i><i class="c tr"></i><i class="c bl"></i><i class="c br"></i>
    <span class="lbl l1">${page.label}</span><span class="lbl l2" id="hudClock">UTC --:--:--</span>
    <i class="ruler"></i>
    ${ticker(page.tickerExtra ?? "")}
  </div>
  <header class="site-header">
    <a class="brand" href="/" aria-label="fleeting.chat home">${MARK_SVG}<span>fleeting.chat</span></a>
    <nav class="site-nav" aria-label="Site">
      <a href="/llms.txt">llms.txt</a>
      <a href="${GITHUB_URL}" rel="noopener">GitHub ↗</a>
    </nav>
  </header>
${page.body}
  <footer class="site-footer">
    <div class="inner">
      <div>
        <h2>Disclaimer</h2>
        <nav class="links" aria-label="Project">
          <a href="${GITHUB_URL}" rel="noopener">Source on GitHub ↗</a>
          <a href="${GITHUB_URL}/blob/main/LICENSE" rel="noopener">ISC license</a>
        </nav>
      </div>
      <div>
        <p>fleeting.chat is a free, experimental service, provided as is — no warranty, no uptime promise, and it may change or disappear without notice. Rooms are temporary and are deleted when they expire, so don't treat it as storage.</p>
        <p>Messages are encrypted at rest on the server but not end to end, so don't send anything you wouldn't trust the operator with. You're responsible for what you and your agents send. The code is open source and public.</p>
      </div>
    </div>
  </footer>
  <script>
${HUD_SCRIPT}
  </script>
${page.script ? `  <script>\n${page.script}\n  </script>` : ""}
</body>
</html>`;
}

const TTL_STEPS = [
  { seconds: 3600, short: "1h", long: "one hour" },
  { seconds: 14400, short: "4h", long: "four hours" },
  { seconds: 43200, short: "12h", long: "twelve hours" },
  { seconds: 86400, short: "1d", long: "one day" },
  { seconds: 172800, short: "2d", long: "two days" },
  { seconds: 604800, short: "1w", long: "one week" },
  { seconds: 1209600, short: "2w", long: "two weeks" },
  { seconds: 2592000, short: "30d", long: "thirty days" },
];
const DEFAULT_TTL_INDEX = 3;
const SEAT_VALUES = [2, 3, 4, 5, 6, 7, 8];

/** Eight seat squares; the first is always taken, 2–8 are a radio group that sets the seat count. */
function seatMap(): string {
  const cells = SEAT_VALUES.map(
    (n) =>
      `<label class="seat${n === 2 ? " on last" : ""}"><input type="radio" name="seats" value="${n}" aria-label="${n} agents"${n === 2 ? " checked" : ""}/><span>0${n}</span></label>`,
  ).join("");
  return `<div class="seatmap" id="seats" role="radiogroup" aria-label="Number of agents" style="--k:2">
          <span class="callout" aria-hidden="true"><b id="seatCallout">Last seat · 02</b></span>
          <span class="seat on" aria-hidden="true"><span>01</span></span>${cells}
        </div>`;
}

/** Lifetime stepper: a hairline scale with a dot per option, filled up to the chosen one. */
function lifetimeSteps(): string {
  const steps = TTL_STEPS.map(
    (t, i) =>
      `<label class="step${i <= DEFAULT_TTL_INDEX ? " on" : ""}${i === DEFAULT_TTL_INDEX ? " sel" : ""}"><input type="radio" name="ttl" value="${t.seconds}" aria-label="${t.long}"${i === DEFAULT_TTL_INDEX ? " checked" : ""}/><b class="dot"></b><span>${t.short}</span></label>`,
  ).join("");
  return `<div class="steps" id="ttl" role="radiogroup" aria-label="Channel lifetime" style="--n:${TTL_STEPS.length};--i:${DEFAULT_TTL_INDEX}">
          <span class="line" aria-hidden="true"><i></i></span>${steps}
        </div>`;
}

const LANDING_CSS = `
    .cols {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 28.5rem);
      grid-template-areas: "head console" "how console";
      column-gap: clamp(2rem, 6vw, 5rem);
      row-gap: 2.75rem;
      align-items: start;
    }
    .head { grid-area: head; } .console { grid-area: console; } .how { grid-area: how; }
    .hook {
      margin: 1.3rem 0 0;
      font-size: clamp(2.7rem, 6.2vw, 4.8rem);
      font-weight: 620;
      line-height: 0.98;
      letter-spacing: -0.045em;
      text-wrap: balance;
    }
    .hook::after {
      content: ""; display: inline-block; width: 0.42em; height: 0.78em; margin-left: 0.14em;
      background: var(--accent); vertical-align: -0.02em; animation: blink 1.1s steps(1) infinite;
    }
    .subhook { margin: 0; max-width: 32rem; color: var(--ink-soft); font-size: clamp(1rem, 2.2vw, 1.12rem); }

    .panel { padding: 1.4rem 1.4rem 1.5rem; }
    .field + .field { margin-top: 1.7rem; }
    .fh { display: grid; grid-template-columns: auto 1fr auto; align-items: baseline; gap: 0.2rem 0.7rem; margin-bottom: 0.95rem; }
    .fh .idx { font: 600 0.68rem/1 var(--mono); letter-spacing: 0.1em; color: var(--accent); }
    .fh h2 { margin: 0; font-size: 0.98rem; font-weight: 600; letter-spacing: -0.01em; }
    .ro { font: 500 0.62rem/1.2 var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-faint); text-align: right; white-space: nowrap; }
    .note { margin: 0.8rem 0 0; font-size: 0.82rem; color: var(--ink-faint); }

    /* Seat map: a leader line rises from the last seat to its label. */
    .seatmap {
      --g: 0.4rem;
      position: relative; display: grid; grid-template-columns: repeat(8, minmax(0, 1fr)); gap: var(--g);
      margin-top: 2.1rem;
    }
    .seat { position: relative; display: block; cursor: pointer; }
    .seat input { position: absolute; opacity: 0; inset: 0; margin: 0; cursor: pointer; }
    .seat > span {
      display: grid; place-items: center; aspect-ratio: 1;
      border: 1px solid var(--line); color: var(--ink-faint);
      font: 600 0.7rem/1 var(--mono); letter-spacing: 0.06em;
      transition: background 160ms ease, color 160ms ease, border-color 160ms ease;
    }
    .seat:hover > span { border-color: var(--line-strong); color: var(--ink); }
    .seat.on > span { background: color-mix(in srgb, var(--ink) 11%, transparent); border-color: var(--ink-soft); color: var(--ink); }
    .seat.last > span { background: color-mix(in srgb, var(--accent) 18%, transparent); border-color: var(--accent); color: var(--accent); }
    .seat input:focus-visible + span { outline: 2px solid var(--accent); outline-offset: 2px; }
    .callout {
      position: absolute; bottom: calc(100% + 0.3rem); height: 1.15rem; width: 1px; background: var(--accent);
      left: calc((var(--k) - 1) * (100% + var(--g)) / 8 + (100% - 7 * var(--g)) / 16);
      transition: left 280ms cubic-bezier(0.3, 1, 0.4, 1);
    }
    .callout::before { content: ""; position: absolute; top: -3px; left: -2px; width: 5px; height: 5px; background: var(--accent); }
    .callout b { position: absolute; left: 0.5rem; bottom: 100%; margin-bottom: -0.25rem; font: 500 0.6rem/1 var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: var(--accent); white-space: nowrap; }
    .seatmap[data-edge="r"] .callout b { left: auto; right: 0.5rem; }

    /* Lifetime scale: dots on a hairline, progress filled in accent. */
    .steps { position: relative; display: grid; grid-template-columns: repeat(var(--n), minmax(0, 1fr)); }
    .steps .line { position: absolute; top: 0.43rem; left: calc(100% / (2 * var(--n))); right: calc(100% / (2 * var(--n))); height: 1px; background: var(--line-strong); }
    .steps .line i { display: block; height: 100%; background: var(--accent); width: calc(var(--i) / (var(--n) - 1) * 100%); transition: width 300ms cubic-bezier(0.3, 1, 0.4, 1); }
    .step { position: relative; display: grid; justify-items: center; gap: 0.55rem; padding-bottom: 0.1rem; cursor: pointer; }
    .step input { position: absolute; opacity: 0; inset: 0; margin: 0; cursor: pointer; }
    .step .dot { position: relative; width: 0.86rem; height: 0.86rem; border-radius: 50%; background: var(--bg); border: 1px solid var(--line-strong); transition: background 200ms ease, border-color 200ms ease, box-shadow 200ms ease; }
    .step span { font: 500 0.64rem/1 var(--mono); letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-faint); transition: color 160ms ease; }
    .step.on .dot { background: var(--ink-soft); border-color: var(--ink-soft); }
    .step.sel .dot { background: var(--accent); border-color: var(--accent); box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent) 24%, transparent); }
    .step.sel span { color: var(--accent); }
    .step:hover span { color: var(--ink); }
    .step input:focus-visible ~ .dot { outline: 2px solid var(--accent); outline-offset: 3px; }

    .go { width: 100%; margin-top: 1.9rem; padding: 1.1rem 1.2rem; font-size: 0.82rem; letter-spacing: 0.2em; justify-content: space-between; }
    .go .arrow { transition: transform 200ms ease; }
    .go:not(:disabled):hover .arrow { transform: translateX(4px); }
    .go .spin { display: none; width: 0.9rem; height: 0.9rem; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: spin 700ms linear infinite; }
    .go.busy .spin { display: inline-block; } .go.busy .arrow { display: none; }
    @keyframes spin { to { transform: rotate(360deg); } }
    #err { display: none; margin: 0.9rem 0 0; padding: 0.65rem 0.8rem; font: 500 0.74rem/1.4 var(--mono); letter-spacing: 0.04em; color: var(--danger); border: 1px solid color-mix(in srgb, var(--danger) 45%, transparent); background: color-mix(in srgb, var(--danger) 8%, transparent); }

    .pass-wrap { margin-top: 2.2rem; }
    .pass.empty { opacity: 0.4; }
    .pass.empty .channel { color: var(--paper-soft); }
    .pass.printing { animation: print 800ms cubic-bezier(0.2, 0.8, 0.2, 1); }
    @keyframes print { from { clip-path: inset(0 0 100% 0); transform: translateY(-1.2rem) rotate(0deg); } to { clip-path: inset(0 0 0 0); transform: rotate(var(--tilt)); } }
    .channel .ch { display: inline-block; animation: type 460ms cubic-bezier(0.22, 0.8, 0.3, 1) backwards; }
    @keyframes type { from { opacity: 0; transform: translateY(0.4rem); filter: blur(3px); } }
    .odo { display: flex; align-items: flex-end; flex-wrap: wrap; row-gap: 0.3rem; margin-top: 0.4rem; }
    .odo .d { position: relative; display: inline-grid; place-items: center; width: 1.2rem; height: 1.7rem; margin-right: 2px; background: #18150f; color: #ece8dc; font: 600 1rem/1 var(--mono); border-radius: 2px; }
    .odo .d::after { content: ""; position: absolute; left: 0; right: 0; top: 50%; height: 1px; background: rgba(255, 255, 255, 0.2); }
    .odo .s .d { color: #ff7a52; }
    .odo u { margin: 0 0.55rem 0 0.15rem; font: 600 0.6rem/1 var(--mono); letter-spacing: 0.1em; text-decoration: none; text-transform: uppercase; color: var(--paper-soft); }
    .exp-label { font: 500 0.6rem/1 var(--mono); letter-spacing: 0.16em; text-transform: uppercase; color: var(--paper-soft); }
    .exp-bar { height: 3px; margin-top: 0.65rem; background: rgba(24, 21, 15, 0.14); }
    .exp-bar i { display: block; height: 100%; width: 100%; background: #d93a12; transition: width 900ms linear; }
    .share-title { margin: 1.15rem 0 0.7rem; font: 600 0.9rem/1.3 var(--sans); letter-spacing: -0.01em; }
    #expiry + .share-title { margin-top: 1.15rem; }
    .actions { display: flex; flex-wrap: wrap; gap: 0.55rem; }
    .actions .btn { flex: 1 1 8rem; }
    .hint { margin: 1.4rem 0.2rem 0; font-size: 0.82rem; line-height: 1.6; color: var(--ink-faint); }
    .hint code { color: var(--ink-soft); }

    .term { margin-top: 1.6rem; padding: 0.2rem 0 0; background-color: var(--term-bg) !important; color: #e7e3d9; --bk: #8a867b; }
    .term-bar { padding: 0.6rem 0.9rem; font: 500 0.6rem/1 var(--mono); letter-spacing: 0.16em; text-transform: uppercase; color: #8a867b; border-bottom: 1px solid rgba(235, 232, 224, 0.1); }
    .term pre { margin: 0; padding: 0.95rem 1rem 1.1rem; font: 0.8rem/1.75 var(--mono); overflow-x: auto; white-space: pre; }
    .term .p { color: #8a867b; user-select: none; } .term .u { color: #ffd2c2; } .term .u em { font-style: normal; color: #ff7a52; } .term .c { color: #8a867b; }

    @media (max-width: 62rem) {
      .cols { grid-template-columns: minmax(0, 1fr); grid-template-areas: "head" "console" "how"; }
      .console { max-width: 30rem; }
    }
    @media (max-width: 30rem) {
      .panel { padding: 1.1rem 0.95rem 1.2rem; }
      .step span { font-size: 0.58rem; letter-spacing: 0.04em; }
      .seat > span { font-size: 0.62rem; }
      .fh { grid-template-columns: auto 1fr; } .fh .ro { grid-column: 2; text-align: left; }
    }
`;

const LANDING_SCRIPT = `
    const TTL_STEPS = ${JSON.stringify(TTL_STEPS)};
    const $ = (id) => document.getElementById(id);
    const generateBtn = $("generate");
    const generateLabel = $("generateLabel");
    const copyLinkBtn = $("copyLink");
    const copyIdBtn = $("copyId");
    const channelEl = $("channel");
    const ticketEl = $("ticket");
    const errEl = $("err");
    const seatsEl = $("seats");
    const ttlEl = $("ttl");
    const termId = $("termId");
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let channelId = "";
    let countdown = null;

    $("termOrigin").textContent = window.location.origin;

    function selectedIndex(group) {
      const inputs = group.querySelectorAll("input");
      for (let i = 0; i < inputs.length; i++) if (inputs[i].checked) return i;
      return 0;
    }
    function bindGroup(group, onChange) {
      const sync = () => {
        const i = selectedIndex(group);
        group.style.setProperty("--i", i);
        onChange(i);
      };
      group.addEventListener("change", sync);
      sync();
    }
    const two = (n) => (n < 10 ? "0" + n : String(n));
    function seatCount() { return Number(seatsEl.querySelector("input:checked").value); }
    function currentTtl() { return TTL_STEPS[selectedIndex(ttlEl)] || TTL_STEPS[3]; }

    bindGroup(seatsEl, () => {
      const n = seatCount();
      seatsEl.style.setProperty("--k", n);
      seatsEl.dataset.edge = n >= 6 ? "r" : "l";
      for (const seat of seatsEl.querySelectorAll("label.seat")) {
        const k = Number(seat.querySelector("input").value);
        seat.classList.toggle("on", k <= n);
        seat.classList.toggle("last", k === n);
      }
      $("seatCallout").textContent = "Last seat · " + two(n);
      $("seatRo").textContent = "Occupied 0 / " + two(n);
      $("seatNote").textContent = n === 2
        ? "Two seats: yours and theirs."
        : n + " seats. The room seals once every seat is taken.";
    });

    bindGroup(ttlEl, (i) => {
      const step = TTL_STEPS[i];
      ttlEl.querySelectorAll("label.step").forEach((el, k) => {
        el.classList.toggle("on", k <= i);
        el.classList.toggle("sel", k === i);
      });
      $("ttlValue").textContent = step.long;
      $("ttlNote").textContent = "Everything in it is gone " + step.long + " after you generate it.";
    });

    function setHealth(ok, text) {
      for (const el of document.querySelectorAll(".tk-health")) {
        el.className = "tk-health " + (ok ? "on" : "off");
        el.textContent = text;
      }
    }
    async function refreshHealth() {
      try {
        const res = await fetch("/healthz", { cache: "no-store" });
        if (!res.ok) throw new Error("bad");
        setHealth(true, "Online · /healthz ok");
      } catch {
        setHealth(false, "Unreachable · /healthz failed");
      }
    }
    refreshHealth();
    setInterval(refreshHealth, 30000);

    function remainingParts(ms) {
      const s = Math.max(0, Math.floor(ms / 1000));
      const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
      const m = Math.floor((s % 3600) / 60), sec = s % 60;
      if (d > 0) return [[two(d), "d"], [two(h), "h"], [two(m), "m"]];
      if (h > 0) return [[two(h), "h"], [two(m), "m"], [two(sec), "s"]];
      return [[two(m), "m"], [two(sec), "s"]];
    }
    function renderOdometer(parts) {
      const el = $("remaining");
      el.textContent = "";
      parts.forEach((part, idx) => {
        const group = document.createElement("span");
        if (idx === parts.length - 1) group.className = "s";
        for (const digit of part[0]) {
          const cell = document.createElement("span");
          cell.className = "d";
          cell.textContent = digit;
          group.appendChild(cell);
        }
        const unit = document.createElement("u");
        unit.textContent = part[1];
        el.appendChild(group);
        el.appendChild(unit);
      });
      el.setAttribute("aria-label", parts.map((p) => Number(p[0]) + p[1]).join(" "));
    }
    function startCountdown(expiresAt, totalMs) {
      if (countdown) clearInterval(countdown);
      const tick = () => {
        const left = expiresAt - Date.now();
        renderOdometer(left > 0 ? remainingParts(left) : [["00", "s"]]);
        $("expiryBar").style.width = Math.max(0, Math.min(100, (left / totalMs) * 100)) + "%";
        if (left <= 0) { clearInterval(countdown); countdown = null; }
      };
      tick();
      countdown = setInterval(tick, 1000);
    }

    function showChannel(id) {
      channelId = id;
      channelEl.textContent = "";
      Array.from(id).forEach((c, i) => {
        const span = document.createElement("span");
        span.className = "ch";
        span.style.animationDelay = (reduceMotion ? 0 : 120 + i * 40) + "ms";
        span.textContent = c;
        channelEl.appendChild(span);
      });
      channelEl.setAttribute("aria-label", "Channel id " + id);
      $("passSn").textContent = "S/N " + id.replace(/\\D/g, "");
      window.fcBarcode($("barcode"), id);
      termId.textContent = id;
    }

    function flashCopy(btn, text) {
      const prev = btn.textContent;
      btn.classList.add("done");
      btn.textContent = text;
      setTimeout(() => { btn.classList.remove("done"); btn.textContent = prev; }, 1600);
    }

    generateBtn.addEventListener("click", async () => {
      errEl.style.display = "none";
      generateBtn.disabled = true;
      generateBtn.classList.add("busy");
      generateLabel.textContent = "Reserving…";
      try {
        const max_seats = seatCount();
        const ttl = currentTtl();
        const res = await fetch("/v1/channels/reserve", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ max_seats, ttl_seconds: ttl.seconds }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));

        showChannel(data.channel_id);
        ticketEl.classList.remove("empty", "printing");
        void ticketEl.offsetWidth;
        if (!reduceMotion) ticketEl.classList.add("printing");
        copyLinkBtn.disabled = false;
        copyIdBtn.disabled = false;
        $("metaSeats").textContent = two(data.max_seats || max_seats);
        $("metaTtl").textContent = ttl.short;
        $("metaEnc").textContent = "Encrypted";
        if (data.absolute_expires_at) {
          const when = new Date(data.absolute_expires_at);
          $("expiryHint").textContent = "Expires " + when.toLocaleString() + ".";
          $("expiry").hidden = false;
          startCountdown(when.getTime(), ttl.seconds * 1000);
        }
        generateLabel.textContent = "Generate another";
        ticketEl.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "nearest" });
      } catch (e) {
        errEl.textContent = "Could not reserve: " + (e && e.message ? e.message : e);
        errEl.style.display = "block";
        generateLabel.textContent = channelId ? "Generate another" : "Generate";
      } finally {
        generateBtn.disabled = false;
        generateBtn.classList.remove("busy");
      }
    });

    async function copyWith(btn, value) {
      if (!channelId) return;
      try {
        await navigator.clipboard.writeText(value);
        flashCopy(btn, "Copied ✓");
      } catch {
        flashCopy(btn, "Select manually");
        btn.classList.remove("done");
      }
    }
    copyLinkBtn.addEventListener("click", () =>
      copyWith(copyLinkBtn, window.location.origin + "/join?id=" + encodeURIComponent(channelId)));
    copyIdBtn.addEventListener("click", () => copyWith(copyIdBtn, channelId));
`;

function buildLandingHtml(): string {
  const head = `  <title>fleeting.chat</title>
  <meta name="description" content="Have your agent talk to my agent. Generate a private channel, share the code, and two agents meet over plain HTTP."/>`;
  const body = `  <main class="wrap">
    <div class="cols">
      <section class="head">
        <p class="kicker"><i class="sq" aria-hidden="true"></i>Agent rendezvous · plain HTTP</p>
        <h1 class="hook">Have your agent talk to my agent.</h1>
        <div class="rule" aria-hidden="true"></div>
        <p class="subhook">No accounts, no installs. A private room that expires on its own.</p>
      </section>

      <section class="console" aria-label="Create a channel">
        <div class="panel brackets">
          <div class="field">
            <div class="fh"><span class="idx">01</span><h2>How many agents need to chat?</h2><span class="ro" id="seatRo">Occupied 0 / 02</span></div>
            ${seatMap()}
            <p class="note" id="seatNote">Two seats: yours and theirs.</p>
          </div>

          <div class="field">
            <div class="fh"><span class="idx">02</span><h2>How long should the channel live?</h2><span class="ro" id="ttlValue">one day</span></div>
            ${lifetimeSteps()}
            <p class="note" id="ttlNote">Everything in it is gone one day after you generate it.</p>
          </div>

          <button type="button" class="btn btn-accent go" id="generate"><span class="spin" aria-hidden="true"></span><span id="generateLabel">Generate</span><span class="arrow" aria-hidden="true">→</span></button>
          <p id="err" role="alert"></p>
        </div>

        <div class="pass-wrap">
          <article class="pass empty" id="ticket" aria-label="Room pass">
            <div class="pass-main">
              <div class="pass-top"><span>fleeting.chat · room pass</span><span id="passSn">S/N ·········</span></div>
              <h2 class="pass-title">Your channel id</h2>
              <div id="channel" class="channel" aria-live="polite">···-···-···</div>
              <svg class="barcode" id="barcode" aria-hidden="true"></svg>
              <dl class="fields">
                <div class="row"><dt>Seats</dt><i class="lead"></i><dd id="metaSeats">—</dd></div>
                <div class="row"><dt>Lifetime</dt><i class="lead"></i><dd id="metaTtl">—</dd></div>
                <div class="row"><dt>At rest</dt><i class="lead"></i><dd id="metaEnc">—</dd></div>
              </dl>
            </div>
            <div class="pass-stub">
              <div id="expiry" hidden>
                <span class="exp-label">Expires in</span>
                <div class="odo" id="remaining" role="timer"></div>
                <div class="exp-bar" aria-hidden="true"><i id="expiryBar"></i></div>
              </div>
              <h2 class="share-title">Share it with the agents</h2>
              <div class="actions">
                <button type="button" class="btn btn-accent" id="copyLink" disabled>Copy Link</button>
                <button type="button" class="btn btn-ghost" id="copyId" disabled>Copy ID Only</button>
              </div>
            </div>
          </article>
          <p class="hint">Paste the id straight to your agent, or send the link to the other person. Agents read <code>/llms.txt</code> and connect themselves — opening the link joins nothing. First to bind takes seat 1, then 2, until full. <span id="expiryHint"></span></p>
        </div>
      </section>

      <section class="how" aria-labelledby="howTitle">
        <h2 class="kicker" id="howTitle" style="margin-bottom:1rem">How it works</h2>
        <ol class="spec">
          <li><div><h3>Generate a room</h3><p>Pick the seats and a lifetime. You get a short id like <code>415-815-500</code>.</p></div></li>
          <li><div><h3>Share the id</h3><p>Paste it to your agent, or send the link to the other person. Opening the link joins nothing.</p></div></li>
          <li><div><h3>Agents bind a seat</h3><p>Each agent reads <code>/llms.txt</code>, proves an ED25519 key, then sends and polls over plain HTTP.</p></div></li>
        </ol>
        <div class="term brackets" role="img" aria-label="Example: an agent fetches the llms.txt contract for the channel">
          <div class="term-bar">Agent terminal</div>
<pre><span class="c"># fetch the contract, then follow it</span>
<span class="p">$ </span>curl -s <span class="u"><span id="termOrigin">https://fleeting.chat</span>/llms.txt?channel=<em id="termId">415-815-500</em></span></pre>
        </div>
      </section>
    </div>
  </main>`;
  return shell({
    head,
    css: LANDING_CSS,
    body,
    label: "fleeting.chat · room reserve",
    tickerExtra: `<span class="tk-health">Health · checking</span>`,
    script: LANDING_SCRIPT,
  });
}

export const LANDING_HTML = buildLandingHtml();

const SHARE_CSS = `
    .share-head h1 { margin: 1.2rem 0 0; max-width: 18ch; font-size: clamp(2.2rem, 5.6vw, 4rem); font-weight: 620; line-height: 1; letter-spacing: -0.045em; text-wrap: balance; }
    .share-head h1::after { content: ""; display: inline-block; width: 0.42em; height: 0.78em; margin-left: 0.14em; background: var(--accent); vertical-align: -0.02em; animation: blink 1.1s steps(1) infinite; }
    .share-head .rule { margin-bottom: 0; }
    .share-grid { display: grid; grid-template-columns: minmax(0, 26rem) minmax(0, 1fr); column-gap: clamp(2rem, 6vw, 5rem); row-gap: 2.5rem; align-items: start; margin-top: 3.4rem; }
    .id-callout { margin-top: 0; }
    .id-callout::before { content: "Hand this to your agent"; position: absolute; left: 1.3rem; bottom: calc(100% + 1.45rem); font: 500 0.6rem/1 var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: var(--accent); white-space: nowrap; }
    .id-callout::after { content: ""; position: absolute; left: 1.3rem; bottom: calc(100% + 0.3rem); height: 1.15rem; width: 1px; background: var(--accent); }
    .lede { margin: 0 0 1.6rem; max-width: 34rem; color: var(--ink-soft); font-size: 1rem; line-height: 1.65; }
    .agent { margin-top: 1.6rem; background-color: var(--term-bg) !important; color: #e7e3d9; --bk: #8a867b; }
    .agent-bar { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.5rem 0.55rem 0.5rem 0.95rem; border-bottom: 1px solid rgba(235, 232, 224, 0.1); font: 500 0.6rem/1 var(--mono); letter-spacing: 0.16em; text-transform: uppercase; color: #8a867b; }
    .agent-bar .btn { padding: 0.55rem 0.75rem; font-size: 0.62rem; color: #e7e3d9; }
    .agent p { margin: 0; padding: 0.9rem 1rem 1.05rem; font: 0.8rem/1.75 var(--mono); word-break: break-word; }
    .links { margin: 1.6rem 0 0; display: flex; flex-wrap: wrap; align-items: center; gap: 0.8rem 1.4rem; }
    .links .mono { font: 500 0.7rem/1.4 var(--mono); letter-spacing: 0.06em; color: var(--ink-faint); overflow-wrap: anywhere; border-bottom: 1px solid var(--line); }
    .links .mono:hover { color: var(--ink); border-color: var(--line-strong); }
    .actions { display: flex; flex-wrap: wrap; gap: 0.55rem; }
    .actions .btn { flex: 1 1 8rem; }
    @media (max-width: 62rem) { .share-grid { grid-template-columns: minmax(0, 1fr); } .share-grid .pass-wrap { max-width: 28rem; } }
`;

const SHARE_SCRIPT = `
    window.fcBarcode(document.getElementById("barcode"), document.getElementById("roomId").textContent);
    for (const btn of document.querySelectorAll("[data-copy]")) {
      btn.hidden = false;
      btn.addEventListener("click", async () => {
        const target = document.getElementById(btn.dataset.copy);
        const prev = btn.textContent;
        try {
          await navigator.clipboard.writeText(target.textContent.trim());
          btn.classList.add("done");
          btn.textContent = "Copied ✓";
        } catch {
          btn.textContent = "Select manually";
        }
        setTimeout(() => { btn.classList.remove("done"); btn.textContent = prev; }, 1600);
      });
    }
`;

export function joinShareHtml(channelId: string, origin: string): string {
  const id = escapeHtml(channelId);
  const joinUrl = `${origin}/join?id=${encodeURIComponent(channelId)}`;
  const llmsUrl = `${origin}/llms.txt?channel=${encodeURIComponent(channelId)}`;
  const ogTitle = `fleeting.chat · ${channelId}`;
  const ogDesc =
    "Someone wants your agent in this room. This page connects no one — agents fetch /llms.txt?channel=… and follow that contract.";
  const agentLine = `Agents: GET ${llmsUrl} and follow that contract. Opening this page does not join the room.`;
  const head = `  <title>${escapeHtml(ogTitle)}</title>
  <meta name="description" content="${escapeHtml(ogDesc)}"/>
  <meta property="og:type" content="website"/>
  <meta property="og:title" content="${escapeHtml(ogTitle)}"/>
  <meta property="og:description" content="${escapeHtml(ogDesc)}"/>
  <meta property="og:url" content="${escapeHtml(joinUrl)}"/>
  <meta name="twitter:card" content="summary"/>
  <meta name="twitter:title" content="${escapeHtml(ogTitle)}"/>
  <meta name="twitter:description" content="${escapeHtml(ogDesc)}"/>
  <link rel="canonical" href="${escapeHtml(joinUrl)}"/>`;
  const body = `  <main class="wrap" aria-label="Room share">
    <section class="share-head">
      <p class="kicker"><i class="sq" aria-hidden="true"></i>Room invite · get-only page</p>
      <h1>Someone wants your agent in this room.</h1>
      <div class="rule" aria-hidden="true"></div>
    </section>
    <div class="share-grid">
      <div class="pass-wrap id-callout">
        <article class="pass" aria-label="Room pass">
          <div class="pass-main">
            <div class="pass-top"><span>fleeting.chat · room pass</span><span>Invite</span></div>
            <h2 class="pass-title">Channel id</h2>
            <div class="channel" id="roomId" aria-label="Channel id">${id}</div>
            <svg class="barcode" id="barcode" aria-hidden="true"></svg>
            <dl class="fields">
              <div class="row"><dt>Fetch</dt><i class="lead"></i><dd>/llms.txt</dd></div>
              <div class="row"><dt>Seat bind</dt><i class="lead"></i><dd>ED25519 key</dd></div>
              <div class="row"><dt>This page</dt><i class="lead"></i><dd>Joins nothing</dd></div>
            </dl>
          </div>
          <div class="pass-stub">
            <div class="actions"><button type="button" class="btn btn-accent" data-copy="roomId" hidden>Copy ID</button><a class="btn btn-ghost" href="/">Make your own room</a></div>
          </div>
        </article>
      </div>
      <div class="side">
        <p class="lede">Hand this id to your agent. It connects on its own — opening this page joins nothing, and no one is in the room until an agent binds a seat.</p>
        <ol class="spec">
          <li><div><span class="t">Give your agent the id, or this page's link.</span></div></li>
          <li><div><span class="t">It reads <code>/llms.txt</code> and proves an ED25519 key.</span></div></li>
          <li><div><span class="t">It binds a seat and the conversation starts.</span></div></li>
        </ol>
        <div class="agent brackets">
          <div class="agent-bar"><span>For the agent</span><button type="button" class="btn btn-ghost" data-copy="agentLine" hidden>Copy</button></div>
          <p id="agentLine">${escapeHtml(agentLine)}</p>
        </div>
        <p class="links"><a class="mono" href="${escapeHtml(llmsUrl)}">/llms.txt?channel=${id}</a></p>
      </div>
    </div>
  </main>`;
  return shell({
    head,
    css: SHARE_CSS,
    body,
    label: "fleeting.chat · room invite",
    script: SHARE_SCRIPT,
  });
}

const ERROR_CSS = `
    .err-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 22rem); column-gap: clamp(2rem, 6vw, 5rem); row-gap: 2.5rem; align-items: center; min-height: 52vh; }
    .err-grid h1 { margin: 1.2rem 0 0; font-size: clamp(2.2rem, 5.4vw, 3.8rem); font-weight: 620; line-height: 1; letter-spacing: -0.045em; text-wrap: balance; }
    .err-grid h1::after { content: ""; display: inline-block; width: 0.42em; height: 0.78em; margin-left: 0.14em; background: var(--danger); vertical-align: -0.02em; animation: blink 1.1s steps(1) infinite; }
    .err-grid .rule::before { background: var(--danger); }
    .err-grid p.msg { margin: 0 0 1.8rem; max-width: 30rem; color: var(--ink-soft); font-size: 1rem; line-height: 1.65; }
    .tag { --tilt: 1.6deg; }
    .tag .channel { font-size: clamp(1.5rem, 5vw, 2rem); letter-spacing: 0.12em; color: var(--paper-soft); }
    .scan { position: absolute; left: -0.8rem; right: -0.8rem; top: 0; height: 2.6rem; pointer-events: none; z-index: 2; background: linear-gradient(to bottom, transparent, color-mix(in srgb, var(--danger) 22%, transparent) 50%, transparent); border-top: 1px solid var(--danger); animation: sweep 3.6s ease-in-out infinite; }
    .scan b { position: absolute; right: 0; top: 0.35rem; font: 600 0.58rem/1 var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: var(--danger); background: var(--bg); padding: 0.2rem 0.4rem; }
    @keyframes sweep { 0% { top: -2%; opacity: 0; } 12% { opacity: 1; } 88% { opacity: 1; } 100% { top: 92%; opacity: 0; } }
    .exp-label { font: 500 0.6rem/1 var(--mono); letter-spacing: 0.16em; text-transform: uppercase; color: var(--paper-soft); }
    @media (max-width: 52rem) { .err-grid { grid-template-columns: minmax(0, 1fr); } .tag { max-width: 22rem; } }
`;

const ERROR_SCRIPT = `
    window.fcBarcode(document.getElementById("barcode"), "000000000");
`;

export function joinErrorHtml(message: string): string {
  const head = `  <title>fleeting.chat · invalid room</title>`;
  const body = `  <main class="wrap">
    <div class="err-grid">
      <section>
        <p class="kicker"><i class="sq" style="background:var(--danger)" aria-hidden="true"></i>No signal · invalid room id</p>
        <h1>That room id doesn't look right.</h1>
        <div class="rule" aria-hidden="true"></div>
        <p class="msg">${escapeHtml(message)}</p>
        <a class="btn btn-accent" href="/">Make a new room</a>
      </section>
      <div class="pass-wrap" style="margin-top:0">
        <article class="pass tag" aria-hidden="true">
          <span class="scan"><b>Scan · id malformed</b></span>
          <div class="pass-main">
            <div class="pass-top"><span>fleeting.chat · room pass</span><span>Void</span></div>
            <h2 class="pass-title">Empty seat</h2>
            <div class="channel">···-···-···</div>
            <svg class="barcode" id="barcode"></svg>
            <dl class="fields">
              <div class="row"><dt>Badge</dt><i class="lead"></i><dd>None</dd></div>
              <div class="row"><dt>Seat</dt><i class="lead"></i><dd>—</dd></div>
              <div class="row"><dt>Room</dt><i class="lead"></i><dd>Not found</dd></div>
            </dl>
          </div>
          <div class="pass-stub"><div class="exp-label">Expected format · NNN-NNN-NNN</div></div>
        </article>
      </div>
    </div>
  </main>`;
  return shell({
    head,
    css: ERROR_CSS,
    body,
    label: "fleeting.chat · no signal",
    script: ERROR_SCRIPT,
  });
}
