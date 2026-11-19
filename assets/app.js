(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const heading = $('device-title');
  const button = $('jailbreak');
  const output = $('console');
  const save = $('save-log');
  const engine = window.wobkot;

  const match = /PlayStation\s+(\d+)[/ ](\d+)\.(\d+)/.exec(navigator.userAgent);
  let ready = false;

  // Reveal the log only when the engine actually writes something to it.
  if (engine) {
    const log = engine.logger.log.bind(engine.logger);
    engine.logger.log = (...args) => {
      output.hidden = false;
      save.hidden = false;
      return log(...args);
    };
  }

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
    output.hidden = false;
    save.hidden = true;
    engine.logger.info('Launching...');

    Promise.resolve()
      .then(() => engine.start())
      .catch((err) => {
        engine.logger.error(err && err.stack ? err.stack : String(err));
      });
  });

  save.addEventListener('click', () => {
    const blob = new Blob([output.textContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = `wobkot-log-${Date.now()}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  });
})();
