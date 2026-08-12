/* UTC saatleri tarayıcının yerel saat dilimine çevirir.
   Kullanım: <span class="lt" data-utc="YYYY-MM-DD HH:MM:SS">...</span>
   data-utc UTC kabul edilir; metin toLocaleString() ile değiştirilir. */
(function () {
    function localize(root) {
        var nodes = (root || document).querySelectorAll('span.lt[data-utc]');
        for (var i = 0; i < nodes.length; i++) {
            var el = nodes[i];
            if (el.dataset.done) continue;
            var raw = (el.dataset.utc || '').trim();
            if (!raw || raw === '-') continue;
            var d = new Date(raw.replace(' ', 'T') + 'Z');
            if (!isNaN(d.getTime())) {
                el.textContent = d.toLocaleString();
                el.dataset.done = '1';
            }
        }
    }
    window.localizeTimes = localize;
    if (document.readyState !== 'loading') {
        localize();
    } else {
        document.addEventListener('DOMContentLoaded', function () { localize(); });
    }
})();
