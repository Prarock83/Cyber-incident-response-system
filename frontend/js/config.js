/**
 * CIRS dashboard runtime configuration.
 *
 * Resolution order:
 *   1. ?api=https://your-api.example.com/api   (handy for testing a branch deploy)
 *   2. localStorage.cirs_api_base              (set from the browser console when needed)
 *   3. <meta name="cirs-api-base" content="..."> in index.html
 *   4. window.CIRS_API_BASE
 *   5. http://localhost:3000/api on localhost / file://
 *   6. PRODUCTION_API_BASE below
 *
 * Update PRODUCTION_API_BASE to your deployed backend URL after deploying
 * (see docs/DEPLOYMENT.md). No production page falls back to localhost.
 */
(function () {
  'use strict';

  var PRODUCTION_API_BASE = 'https://cirs-api.onrender.com/api';

  function normalise(value) {
    var url = String(value || '').trim();
    if (!url) return '';
    url = url.replace(/\/+$/, '');
    if (!/\/api$/i.test(url)) url += '/api';
    return url;
  }

  function resolve() {
    try {
      var params = new URLSearchParams(window.location.search);
      var fromQuery = normalise(params.get('api'));
      if (fromQuery) return fromQuery;

      var fromStorage = normalise(window.localStorage.getItem('cirs_api_base'));
      if (fromStorage) return fromStorage;

      var meta = document.querySelector('meta[name="cirs-api-base"]');
      if (meta && meta.content) return normalise(meta.content);

      if (window.CIRS_API_BASE) return normalise(window.CIRS_API_BASE);

      var host = window.location.hostname;
      var isLocal = host === 'localhost' || host === '127.0.0.1' || host === '' || window.location.protocol === 'file:';
      return isLocal ? 'http://localhost:3000/api' : normalise(PRODUCTION_API_BASE);
    } catch (err) {
      return normalise(PRODUCTION_API_BASE);
    }
  }

  window.CIRS_CONFIG = {
    apiBase: resolve(),
    version: '2.0.0',
    isLocal: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.protocol === 'file:',
  };
}());
