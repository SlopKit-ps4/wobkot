(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const heading = $('device-title');
  const button = $('jailbreak');
  const output = $('console');
  const engine = window.wobkot;

  const match = /PlayStation\s+(\d+)[/ ](\d+)\.(\d+)/.exec(navigator.userAgent);
  let ready = false;
  let usePs4jb = false;

  // Reveal the log only when the engine actually writes something to it.
  if (engine) {
    const log = engine.logger.log.bind(engine.logger);
    engine.logger.log = (...args) => {
      output.hidden = false;
      return log(...args);
    };
  }

  if (match) {
    const consoleNum = Number.parseInt(match[1], 10);
    const major = Number.parseInt(match[2], 10);
    const minor = Number.parseInt(match[3], 16);

    if (consoleNum === 4 || consoleNum === 5) {
      const minorHex = minor.toString(16).padStart(2, '0');
      const label = `PS${consoleNum} ${major}.${minorHex}`;
      heading.textContent = label;
      document.title = label;

      // 12.50-13.00 needs the poops chain, which wobkot does not implement.
      if (consoleNum === 4) {
        const fwnum = major * 100 + Number.parseInt(minorHex, 10);
        usePs4jb = fwnum === 1250 || fwnum === 1252 || fwnum === 1300;
      }

      ready = Boolean(engine) || usePs4jb;
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

    if (usePs4jb) {
      window.location.href = 'ps4jb/index.html';
      return;
    }

    output.textContent = '';
    output.hidden = false;
    engine.logger.info('Launching...');

    Promise.resolve()
      .then(() => engine.start())
      .catch((err) => {
        engine.logger.error(err && err.stack ? err.stack : String(err));
      });
  });
})();
