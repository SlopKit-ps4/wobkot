(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const ui = {
    consoleType: $('device-console'),
    version: $('device-version'),
    status: $('device-status'),
    launch: $('launch'),
    clear: $('clear'),
    note: $('launch-note'),
  };

  const match = /PlayStation\s+(\d+)[/ ](\d+)\.(\d+)/.exec(navigator.userAgent);
  const engine = window.wobkot;
  let ready = false;

  if (match) {
    const consoleNum = Number.parseInt(match[1], 10);
    const major = Number.parseInt(match[2], 10);
    const minor = Number.parseInt(match[3], 16);

    ui.consoleType.textContent = `PS${consoleNum}`;
    ui.version.textContent = `${major}.${minor.toString(16).padStart(2, '0')}`;

    if (consoleNum === 4 || consoleNum === 5) {
      ui.status.textContent = 'Supported';
      ui.status.style.color = 'var(--accent)';
      ready = Boolean(engine);
    } else {
      ui.status.textContent = 'Unsupported console';
      ui.status.style.color = 'var(--warn)';
      ui.note.textContent = 'This userland supports PS4 and PS5 only.';
    }
  } else {
    ui.consoleType.textContent = 'Not detected';
    ui.version.textContent = '—';
    ui.status.textContent = 'Open in a PlayStation browser';
    ui.status.style.color = 'var(--warn)';
    ui.note.textContent = 'Console detection failed. The exploit engine is loaded, but launch is disabled here.';
  }

  if (!engine) {
    ui.status.textContent = 'Engine failed to load';
    ui.status.style.color = 'var(--warn)';
    ready = false;
  }

  ui.launch.disabled = !ready;

  ui.launch.addEventListener('click', () => {
    if (!ready) return;

    ui.launch.disabled = true;
    ui.note.textContent = 'Running — watch the console output below.';
    engine.logger.info('Launching wobkot...');

    Promise.resolve()
      .then(() => engine.start())
      .catch((err) => {
        engine.logger.error(err && err.stack ? err.stack : String(err));
        ui.note.textContent = 'Launch failed. See console output.';
      });
  });

  ui.clear.addEventListener('click', () => {
    $('console').textContent = '';
  });
})();
