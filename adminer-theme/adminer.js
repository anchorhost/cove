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

  /* ---------- Theme ---------- */
  function readTheme() {
    try {
      var s = localStorage.getItem(KEY_THEME);
      if (s === 'dark' || s === 'light') return s;
    } catch (e) {}
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(t) {
    html.setAttribute('data-theme', t);
    try { localStorage.setItem(KEY_THEME, t); } catch (e) {}
    var btn = document.querySelector('.cove-theme-toggle');
    if (btn) {
      btn.setAttribute(
        'aria-label',
        t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'
      );
    }
  }

  if (!html.hasAttribute('data-theme')) {
    html.setAttribute('data-theme', readTheme());
  }

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

  function makeToggle() {
    if (document.querySelector('.cove-theme-toggle')) return;

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'cove-theme-toggle';
    btn.setAttribute('aria-label', 'Toggle theme');
    btn.innerHTML = SUN + MOON;
    btn.addEventListener('click', function () {
      var current = html.getAttribute('data-theme') || 'light';
      applyTheme(current === 'dark' ? 'light' : 'dark');
    });

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
