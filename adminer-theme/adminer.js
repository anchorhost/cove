/**
 * Cove — Adminer UI enhancements.
 * Pairs with adminer.css. Adds:
 *   - Explicit light/dark theme toggle (persisted in localStorage).
 *   - Drag-to-resize sidebar (persisted in localStorage).
 *
 * index.php emits a tiny inline <script> earlier in <head> that sets
 * data-theme synchronously (before CSS applies) to avoid a theme flash.
 */
(function () {
  var KEY_THEME = 'cove-adminer-theme';
  var KEY_WIDTH = 'cove-adminer-menu-width';
  var MIN_W = 180, MAX_W = 480;
  var html = document.documentElement;

  /* ---------- Theme ----------
     Preference: 'light' | 'dark' | 'system' (default). data-theme carries the
     effective mode the tokens read; data-theme-pref drives the toggle icon.
     Click flips light and dark; right-click picks from a small menu. */
  function readPref() {
    try {
      var s = localStorage.getItem(KEY_THEME);
      if (s === 'dark' || s === 'light') return s;
    } catch (e) {}
    return 'system';
  }
  function osTheme() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  function effective(pref) { return pref === 'system' ? osTheme() : pref; }

  function applyPref(pref) {
    pref = (pref === 'dark' || pref === 'light') ? pref : 'system';
    html.setAttribute('data-theme', effective(pref));
    html.setAttribute('data-theme-pref', pref);
    try { localStorage.setItem(KEY_THEME, pref); } catch (e) {}
    var btn = document.querySelector('.cove-theme-toggle');
    if (btn) {
      var label = { system: 'System', light: 'Light', dark: 'Dark' }[pref];
      btn.setAttribute('aria-label', 'Theme: ' + label + ' (click to switch light and dark, right-click for options)');
      btn.title = btn.getAttribute('aria-label');
    }
    var menu = document.querySelector('.cove-theme-menu');
    if (menu) {
      var items = menu.querySelectorAll('button');
      for (var i = 0; i < items.length; i++) items[i].setAttribute('aria-checked', String(items[i].getAttribute('data-pref') === pref));
    }
  }

  if (!html.hasAttribute('data-theme')) applyPref(readPref());
  try {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if (readPref() === 'system') applyPref('system');
    });
  } catch (e) {}

  /* ---------- Menu width ---------- */
  function clampWidth(w) {
    w = Math.round(w);
    if (w < MIN_W) return MIN_W;
    if (w > MAX_W) return MAX_W;
    return w;
  }

  function applyWidth(w) {
    w = clampWidth(w);
    html.style.setProperty('--menu-width', w + 'px');
    return w;
  }

  // Restore saved width synchronously (before first paint).
  try {
    var savedWidth = parseInt(localStorage.getItem(KEY_WIDTH), 10);
    if (savedWidth >= MIN_W && savedWidth <= MAX_W) applyWidth(savedWidth);
  } catch (e) {}

  /* ---------- Toggle button ---------- */
  var SUN  = '<svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32l1.41-1.41"/></svg>';
  var MOON = '<svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  var SYSTEM = '<svg class="icon-system" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none"/></svg>';

  function makeToggle() {
    if (document.querySelector('.cove-theme-toggle')) return;

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'cove-theme-toggle';
    btn.setAttribute('aria-haspopup', 'menu');
    btn.innerHTML = SYSTEM + SUN + MOON;

    var menu = document.createElement('div');
    menu.className = 'cove-theme-menu';
    menu.setAttribute('role', 'menu');
    menu.hidden = true;
    var prefs = [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']];
    for (var i = 0; i < prefs.length; i++) {
      var item = document.createElement('button');
      item.type = 'button';
      item.setAttribute('role', 'menuitemradio');
      item.setAttribute('data-pref', prefs[i][0]);
      item.textContent = prefs[i][1];
      menu.appendChild(item);
    }
    document.body.appendChild(menu);

    btn.addEventListener('click', function () {
      menu.hidden = true;
      applyPref(effective(readPref()) === 'dark' ? 'light' : 'dark');
    });
    btn.addEventListener('contextmenu', function (e) {
      e.preventDefault();
      menu.hidden = !menu.hidden;
    });
    menu.addEventListener('click', function (e) {
      var b = e.target.closest('[data-pref]');
      if (!b) return;
      applyPref(b.getAttribute('data-pref'));
      menu.hidden = true;
    });
    document.addEventListener('click', function (e) {
      if (!menu.hidden && !e.target.closest('.cove-theme-menu, .cove-theme-toggle')) menu.hidden = true;
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !menu.hidden) menu.hidden = true;
    });
    applyPref(readPref());

    var logout = document.querySelector('.logout');
    if (logout && logout.parentNode) {
      logout.parentNode.insertBefore(btn, logout);
    } else {
      document.body.appendChild(btn);
    }
  }

  /* ---------- Resize handle ---------- */
  function makeResizer() {
    if (document.querySelector('.cove-menu-resize')) return;

    var handle = document.createElement('div');
    handle.className = 'cove-menu-resize';
    handle.setAttribute('aria-hidden', 'true');
    handle.title = 'Drag to resize · double-click to reset';
    document.body.appendChild(handle);

    var active = false;

    handle.addEventListener('pointerdown', function (e) {
      e.preventDefault();
      try { handle.setPointerCapture(e.pointerId); } catch (err) {}
      active = true;
      handle.classList.add('dragging');
      document.body.classList.add('cove-menu-resizing');
    });
    handle.addEventListener('pointermove', function (e) {
      if (!active) return;
      applyWidth(e.clientX);
    });
    function end(e) {
      if (!active) return;
      active = false;
      try { handle.releasePointerCapture(e.pointerId); } catch (err) {}
      handle.classList.remove('dragging');
      document.body.classList.remove('cove-menu-resizing');
      var w = parseInt(html.style.getPropertyValue('--menu-width'), 10);
      if (w) {
        try { localStorage.setItem(KEY_WIDTH, String(w)); } catch (err) {}
      }
    }
    handle.addEventListener('pointerup', end);
    handle.addEventListener('pointercancel', end);
    handle.addEventListener('dblclick', function () {
      html.style.removeProperty('--menu-width');
      try { localStorage.removeItem(KEY_WIDTH); } catch (e) {}
    });
  }

  /* ---------- Brand link ----------
     On the login page Adminer wraps the name in <a id="h1"> pointing at
     adminer.org. On authenticated pages the name is a bare text node.
     Handle both: retarget if the anchor exists, otherwise wrap the text. */
  function retargetBrand() {
    var existing = document.getElementById('h1');
    if (existing && existing.tagName === 'A') {
      existing.setAttribute('href', '?server=&username=');
      existing.removeAttribute('target');
      existing.removeAttribute('rel');
      return;
    }

    var h1 = document.querySelector('#menu h1');
    if (!h1) return;
    for (var node = h1.firstChild; node; node = node.nextSibling) {
      if (node.nodeType === 3 && node.nodeValue.trim()) {
        var a = document.createElement('a');
        a.id = 'h1';
        a.href = '?server=&username=';
        a.textContent = node.nodeValue.trim();
        h1.replaceChild(a, node);
        return;
      }
    }
  }

  function init() {
    makeToggle();
    makeResizer();
    retargetBrand();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
