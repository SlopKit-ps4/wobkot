(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const heading = $('device-title');
  const button = $('jailbreak');
  const output = $('console');
  const engine = window.wobkot;

  const match = /PlayStation\s+(\d+)[/ ](\d+)\.(\d+)/.exec(navigator.userAgent);
  let ready = false;

  if (match) {
    const consoleNum = Number.parseInt(match[1], 10);
    const major = Number.parseInt(match[2], 10);
    const minor = Number.parseInt(match[3], 16);

    if (consoleNum === 4 || consoleNum === 5) {
      const label = `PS${consoleNum} ${major}.${minor.toString(16).padStart(2, '0')}`;
      heading.textContent = label;
      document.title = label;
      ready = Boolean(engine);
    } else {
      heading.textContent = 'Unsupported device';
    }
  } else {
    heading.textContent = 'Not detected';
  }

  button.disabled = !ready;

  button.addEventListener('click', () => {
    if (!ready) return;

    button.disabled = true;
    output.textContent = '';
    engine.logger.info('Launching...');

    Promise.resolve()
      .then(() => engine.start())
      .catch((err) => {
        engine.logger.error(err && err.stack ? err.stack : String(err));
      });
  });
})();
