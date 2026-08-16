/* Panel içi AJAX gezinme — form gönderimlerini yakalar, arka planda çeker ve
   yalnız <main class="wrap"> içeriğini değiştirir; TAM SAYFA YENİLEME OLMAZ.
   Sunucu view'ları değişmeden çalışır: tam HTML döner, biz içerik bölgesini alırız.
   Herhangi bir hatada normal gezinmeye (window.location) düşülür → en kötü ihtimalle
   eski davranış (yenileme), asla bozulmaz. Bir formu hariç tutmak için: data-no-ajax. */
(function () {
    var main = document.querySelector('main.wrap');
    if (!main || !window.fetch || !window.DOMParser || !(window.history && history.pushState)) return;

    // innerHTML ile eklenen <script>'ler çalışmaz → yeniden oluşturup çalıştır.
    function runScripts(root) {
        var scripts = root.querySelectorAll('script');
        for (var i = 0; i < scripts.length; i++) {
            var old = scripts[i], s = document.createElement('script');
            for (var j = 0; j < old.attributes.length; j++) {
                s.setAttribute(old.attributes[j].name, old.attributes[j].value);
            }
            if (!old.src) s.textContent = old.textContent;
            old.parentNode.replaceChild(s, old);
        }
    }

    function swap(html, url, push) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var neu = doc.querySelector('main.wrap');
        if (!neu) { window.location = url; return; }        // beklenmedik yanıt → normal git
        main.innerHTML = neu.innerHTML;
        runScripts(main);
        if (window.localizeTimes) window.localizeTimes(main); // yerel saatleri çevir
        var title = doc.querySelector('title');
        if (title) document.title = title.textContent;
        var oldNav = document.querySelector('.topbar nav'), newNav = doc.querySelector('.topbar nav');
        if (oldNav && newNav) oldNav.innerHTML = newNav.innerHTML; // aktif sekme güncelle
        if (push && url && url !== location.href) history.pushState({ ajax: 1 }, '', url);
        window.scrollTo(0, 0);
    }

    function go(url, opts, push) {
        document.body.classList.add('ajax-busy');
        return fetch(url, opts)
            .then(function (r) { return r.text().then(function (t) { return { html: t, url: r.url }; }); })
            .then(function (res) { swap(res.html, res.url, push); })
            .catch(function () { window.location = url; })    // hata → normal git
            .finally(function () { document.body.classList.remove('ajax-busy'); });
    }

    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!(form instanceof HTMLFormElement) || form.hasAttribute('data-no-ajax')) return;
        e.preventDefault();
        var btn = e.submitter, fd = new FormData(form);
        if (btn && btn.name) fd.append(btn.name, btn.value); // tıklanan butonun name/value'su
        var method = (form.method || 'get').toLowerCase();
        var action = (btn && btn.getAttribute('formaction')) || form.action || location.href;
        if (btn) btn.disabled = true;
        if (method === 'post') {
            go(action, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'fetch' } }, false);
        } else {
            var q = new URLSearchParams(fd).toString();
            go(action.split('?')[0] + (q ? '?' + q : ''), { headers: { 'X-Requested-With': 'fetch' } }, true);
        }
    });

    window.addEventListener('popstate', function () {
        go(location.href, { headers: { 'X-Requested-With': 'fetch' } }, false);
    });
})();
