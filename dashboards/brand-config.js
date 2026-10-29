/* ============================================================
   SOC Lab — Admin-Configurable Branding
   Applies org name, sub-title and logo across every dashboard
   from a single source of truth stored in localStorage.
   Edit via: 00_admin_branding.html
   ============================================================ */
(function () {
  'use strict';

  var STORAGE_KEY = 'soc_brand_config';

  var DEFAULTS = {
    title: 'DBI SOC',
    sub: 'COMMAND CENTER',
    icon: '🛡️',
    logoUrl: ''
  };

  function loadConfig() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return Object.assign({}, DEFAULTS);
      var parsed = JSON.parse(raw);
      return Object.assign({}, DEFAULTS, parsed);
    } catch (e) {
      return Object.assign({}, DEFAULTS);
    }
  }

  function saveConfig(cfg) {
    var merged = Object.assign({}, DEFAULTS, cfg);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
    applyBrand(merged);
    return merged;
  }

  function resetConfig() {
    localStorage.removeItem(STORAGE_KEY);
    applyBrand(Object.assign({}, DEFAULTS));
    return Object.assign({}, DEFAULTS);
  }

  function applyBrand(cfg) {
    document.querySelectorAll('.sidebar-brand .brand-title').forEach(function (el) {
      el.textContent = cfg.title || DEFAULTS.title;
    });

    document.querySelectorAll('.sidebar-brand .brand-sub').forEach(function (el) {
      el.textContent = cfg.sub || DEFAULTS.sub;
    });

    document.querySelectorAll('.sidebar-brand .brand-icon').forEach(function (el) {
      if (cfg.logoUrl) {
        el.textContent = '';
        var img = el.querySelector('img.brand-logo-img');
        if (!img) {
          img = document.createElement('img');
          img.className = 'brand-logo-img';
          img.alt = (cfg.title || DEFAULTS.title) + ' logo';
          img.style.cssText = 'width:26px;height:26px;object-fit:contain;border-radius:6px;display:block;';
          el.appendChild(img);
        }
        img.src = cfg.logoUrl;
      } else {
        el.innerHTML = '';
        el.textContent = cfg.icon || DEFAULTS.icon;
      }
    });

    document.querySelectorAll('.sidebar-footer').forEach(function (el) {
      var brandSpan = el.querySelector('.sidebar-footer-brand');
      if (brandSpan) {
        var suffix = el.getAttribute('data-brand-suffix') || 'OSS';
        brandSpan.textContent = (cfg.title || DEFAULTS.title) + ' · ' + suffix;
      }
    });

    document.querySelectorAll('[data-brand-favicon]').forEach(function (el) {
      el.textContent = cfg.icon && !cfg.logoUrl ? cfg.icon : DEFAULTS.icon;
    });
  }

  function injectFooterAdminLink() {
    document.querySelectorAll('.sidebar-footer').forEach(function (el) {
      if (el.getAttribute('data-brand-init') === '1') return;
      var text = el.textContent.trim();
      var suffix = 'OSS';
      var parts = text.split('·');
      if (parts.length > 1 && parts[1].trim()) suffix = parts[1].trim();
      el.setAttribute('data-brand-suffix', suffix);
      el.setAttribute('data-brand-init', '1');
      el.innerHTML =
        '<span class="sidebar-footer-brand"></span>' +
        '<a href="00_admin_branding.html" title="Branding settings (admin)" ' +
        'style="color:inherit;opacity:0.55;text-decoration:none;margin-left:8px;font-size:12px;">&#9881;</a>';
    });
  }

  function init() {
    injectFooterAdminLink();
    applyBrand(loadConfig());
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.addEventListener('storage', function (e) {
    if (e.key === STORAGE_KEY) applyBrand(loadConfig());
  });

  window.SOC_BRAND = {
    load: loadConfig,
    save: saveConfig,
    reset: resetConfig,
    apply: applyBrand,
    DEFAULTS: DEFAULTS,
    STORAGE_KEY: STORAGE_KEY
  };
})();
