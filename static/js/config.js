// config.js - Global application configuration
window.appConfig = {
  defaultLanguage: 'en'
};

window.setAppLanguage = function(lang) {
  localStorage.setItem('lang', lang);
  // Also update defaultLanguage for future sessions
  window.appConfig.defaultLanguage = lang;
};
