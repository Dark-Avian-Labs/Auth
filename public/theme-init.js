(function () {
  try {
    var root = document.documentElement;
    function readCookie(name) {
      var part = document.cookie
        .split(';')
        .map(function (p) {
          return p.trim();
        })
        .find(function (p) {
          return p.substring(0, name.length + 1) === name + '=';
        });
      if (!part) return null;
      try {
        return decodeURIComponent(part.slice(name.length + 1));
      } catch (e) {
        if (typeof console !== 'undefined' && console && typeof console.warn === 'function') {
          console.warn('Failed to decode cookie "' + name + '"; treating as missing value.', e);
        }
        return null;
      }
    }

    /**
     * @param {string} cookieName
     * @param {string} storageKey
     * @param {string[]} allowed
     * @param {string} defaultValue
     * @param {string} storageErrorMessage
     */
    function readPreference(cookieName, storageKey, allowed, defaultValue, storageErrorMessage) {
      var raw = readCookie(cookieName);
      var value = '';
      if (raw != null && raw !== '') {
        value = String(raw).trim();
      }
      if (allowed.indexOf(value) === -1) {
        try {
          var fromStorage = localStorage.getItem(storageKey);
          if (fromStorage != null && fromStorage !== '') {
            value = String(fromStorage).trim();
          } else {
            value = '';
          }
        } catch (e) {
          if (typeof console !== 'undefined' && console && typeof console.warn === 'function') {
            console.warn(storageErrorMessage, e);
          }
          value = '';
        }
      }
      if (allowed.indexOf(value) === -1) {
        value = defaultValue;
      }
      return value;
    }

    var theme = readPreference(
      'dal.theme.mode',
      'dal.theme.mode',
      ['light', 'dark'],
      'dark',
      'Unable to read theme from localStorage; falling back to default.',
    );
    root.style.colorScheme = theme === 'dark' ? 'dark' : 'light';
    root.classList.toggle('dark', theme === 'dark');

    var ui = readPreference(
      'dal.ui.style',
      'dal.ui.style',
      ['prism', 'shadow'],
      'prism',
      'Unable to read UI style from localStorage; falling back to default.',
    );
    root.classList.remove('ui-prism', 'ui-shadow');
    root.classList.add('ui-' + ui);
  } catch (e) {
    if (typeof console !== 'undefined' && console && typeof console.error === 'function') {
      console.error('Error during theme initialization.', e);
    }
  }
})();
