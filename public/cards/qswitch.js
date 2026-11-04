// Query dialect switch. Every hunt on the site is printed in two dialects inside one block:
//   <div class="qs"><pre data-q="spl">Splunk search</pre><pre data-q="esql">ES|QL twin</pre></div>
// This script adds Splunk | Elastic tabs to each block, shows one dialect at a time and remembers
// the reader's choice for the whole site (localStorage). Without the script both blocks read
// stacked, as before; in print (and so in the card PDFs) both are shown, each under its label.
// Loaded by the hand-written cards (public/cards/*.html) and the site chrome (api/page.js).
(function () {
  try {
    var LANG = { spl: 'Splunk', esql: 'Elastic ES|QL' };
    var KEY = 'cutsign.query_lang';
    var blocks = Array.prototype.slice.call(document.querySelectorAll('.qs'));
    if (!blocks.length) return;
    var st = document.createElement('style');
    st.textContent = '.qs{margin:6px 0}'
      + '.qs .qt{display:flex;gap:4px;margin:8px 0 0}'
      + '.qs .qt button{font:600 11px ui-monospace,SFMono-Regular,Menlo,monospace;padding:3px 10px;border:1px solid rgba(128,128,128,.45);border-bottom:none;border-radius:8px 8px 0 0;background:transparent;color:inherit;opacity:.55;cursor:pointer}'
      + '.qs .qt button[aria-selected="true"]{opacity:1;background:rgba(128,128,128,.14)}'
      + '.qs[data-on] pre[data-q]{display:none;margin-top:0;border-top-left-radius:0}'
      + '.qs[data-on="spl"] pre[data-q="spl"],.qs[data-on="esql"] pre[data-q="esql"]{display:block}'
      + '@media print{.qs .qt{display:none}.qs[data-on] pre[data-q]{display:block;margin-top:6px;border-top-left-radius:inherit}'
      + '.qs pre[data-q]::before{content:attr(data-lang);display:block;font-weight:600;opacity:.7;margin-bottom:6px}}';
    document.head.appendChild(st);
    var saved = null;
    try { saved = localStorage.getItem(KEY); } catch (e) { saved = null; }
    var on = LANG[saved] ? saved : 'spl';
    function apply(lang) {
      on = lang;
      blocks.forEach(function (b) {
        // a block missing the chosen dialect falls back to Splunk rather than going blank
        var show = b.querySelector('pre[data-q="' + lang + '"]') ? lang : 'spl';
        b.setAttribute('data-on', show);
        Array.prototype.forEach.call(b.querySelectorAll('.qt button'), function (btn) {
          btn.setAttribute('aria-selected', btn.getAttribute('data-q') === show ? 'true' : 'false');
        });
      });
    }
    blocks.forEach(function (b) {
      var pres = Array.prototype.slice.call(b.querySelectorAll('pre[data-q]'));
      pres.forEach(function (p) { p.setAttribute('data-lang', LANG[p.getAttribute('data-q')] || p.getAttribute('data-q')); });
      if (pres.length < 2) return; // one dialect only: nothing to switch
      var bar = document.createElement('div');
      bar.className = 'qt'; bar.setAttribute('role', 'tablist'); bar.setAttribute('aria-label', 'Query dialect');
      pres.forEach(function (p) {
        var q = p.getAttribute('data-q');
        var btn = document.createElement('button');
        btn.type = 'button'; btn.setAttribute('role', 'tab'); btn.setAttribute('data-q', q); btn.textContent = LANG[q] || q;
        btn.addEventListener('click', function () {
          apply(q);
          try { localStorage.setItem(KEY, q); } catch (e) { /* private mode: the choice lasts the page */ }
        });
        bar.appendChild(btn);
      });
      b.insertBefore(bar, pres[0]);
    });
    apply(on);
  } catch (e) { /* the stacked blocks remain readable */ }
})();
