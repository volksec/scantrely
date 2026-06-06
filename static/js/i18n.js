/* i18n.js — Language switcher (minimal, non-breaking) */
window.setLanguage = function(lang) {
  localStorage.setItem('lang', lang);
  location.reload();
};
(function(){
  var lang = localStorage.getItem('lang') || 'pt-br';
  document.documentElement.lang = lang;
  document.addEventListener('DOMContentLoaded', function(){
    var sel = document.getElementById('lang-select');
    if (sel) sel.value = lang;
  });
})();
