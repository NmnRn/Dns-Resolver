/* Panel içi AJAX gezinme — form gönderimlerini yakalar, arka planda çeker ve
   yalnız <main class="wrap"> içeriğini değiştirir; TAM SAYFA YENİLEME OLMAZ.
   Sunucu view'ları değişmeden çalışır (tam HTML döner, biz içerik bölgesini alırız).

   Sağlamlık: her adım korumalı — hata olursa normal gezinmeye (window.location) düşer,
   yani en kötü ihtimalle eski davranış (yenileme); panel ASLA bozulmaz. POST'ta kaydırma
   konumu KORUNUR (toggle'da yukarı zıplama yok); tıklanan buton işlem bitince geri açılır.
   Bir formu hariç tutmak için: <form data-no-ajax>. */
(function () {
    var main = document.querySelector('main.wrap');
    if (!main || !window.fetch || !window.DOMParser || !(window.history && history.pushState)) return;

    function runScripts(root) {
        // innerHTML ile eklenen <script>'ler çalışmaz → yeniden oluştur; tek bir script
        // hatası tüm swap'i bozmasın diye her biri ayrı korumalı.
        var scripts = root.querySelectorAll('script');
        for (var i = 0; i < scripts.length; i++) {
            try {
                var old = scripts[i], s = document.createElement('script');
                for (var j = 0; j < old.attributes.length; j++) {
                    s.setAttribute(old.attributes[j].name, old.attributes[j].value);
                }
                if (!old.src) s.textContent = old.textContent;
                old.parentNode.replaceChild(s, old);
            } catch (err) { /* yoksay */ }
        }
    }

    function swap(html, url, keepScroll) {
        var doc;
        try { doc = new DOMParser().parseFromString(html, 'text/html'); }
        catch (e) { window.location = url; return; }
        var neu = doc.querySelector('main.wrap');
        if (!neu) { window.location = url; return; }        // beklenmedik yanıt → normal git
        // Yeni sayfanın stil dosyalarını (sayfa-özel extra_css) head'e ekle (yoksa) —
        // yoksa başka bir sayfaya geçince o sayfanın CSS'i yüklenmez, stilsiz görünür.
        var have = {}, cur = document.head.querySelectorAll('link[rel="stylesheet"]');
        for (var k = 0; k < cur.length; k++) have[cur[k].getAttribute('href')] = 1;
        var css = doc.head ? doc.head.querySelectorAll('link[rel="stylesheet"]') : [];
        for (var m = 0; m < css.length; m++) {
            var href = css[m].getAttribute('href');
            if (href && !have[href]) {
                var nl = document.createElement('link');
                nl.rel = 'stylesheet'; nl.href = href;
                document.head.appendChild(nl);
            }
        }
        var y = window.scrollY;
        main.innerHTML = neu.innerHTML;
        runScripts(main);
        if (window.localizeTimes) { try { window.localizeTimes(main); } catch (e) {} }
        var title = doc.querySelector('title');
        if (title) document.title = title.textContent;
        var oldNav = document.querySelector('.topbar nav'), newNav = doc.querySelector('.topbar nav');
        if (oldNav && newNav) oldNav.innerHTML = newNav.innerHTML; // aktif sekme güncelle
        window.scrollTo(0, keepScroll ? y : 0);                // POST → yerinde kal; gezinme → başa
    }

    function go(url, opts, keepScroll, pushUrl) {
        document.body.classList.add('ajax-busy');
        return fetch(url, opts)
            .then(function (r) {
                if (r.status >= 500) throw new Error('server');    // 500 → normal gezinmeye bırak
                return r.text().then(function (t) { return { html: t, url: r.url }; });
            })
            .then(function (res) {
                swap(res.html, res.url, keepScroll);
                if (pushUrl && res.url && res.url !== location.href) history.pushState({ ajax: 1 }, '', res.url);
            })
            .catch(function () { window.location = url; })         // ağ/hata → normal git
            .finally(function () { document.body.classList.remove('ajax-busy'); });
    }

    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!(form instanceof HTMLFormElement) || form.hasAttribute('data-no-ajax')) return;
        e.preventDefault();
        var btn = e.submitter, fd = new FormData(form);
        if (btn && btn.name) fd.append(btn.name, btn.value);  // tıklanan butonun name/value'su
        // DİKKAT: form.method / form.action, name="method" / name="action" alanlarıyla
        // GÖLGELENİR (o input/select elementini döndürür) → hep getAttribute kullan.
        var method = (form.getAttribute('method') || 'get').toLowerCase();
        var action = (btn && btn.getAttribute('formaction')) || form.getAttribute('action') || location.href;
        if (btn) btn.disabled = true;
        var reenable = function () { if (btn) btn.disabled = false; };  // eski buton silinse de zararsız
        if (method === 'post') {
            go(action, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'fetch' } }, true, false).then(reenable);
        } else {
            var q = new URLSearchParams(fd).toString();
            go(action.split('?')[0] + (q ? '?' + q : ''), { headers: { 'X-Requested-With': 'fetch' } }, false, true).then(reenable);
        }
    });

    // Panel içi bağlantı tıklamalarını da yakala (navbar sayfa geçişleri yenilemesiz).
    // Hariç: yeni-sekme/modifier tıklamalar, data-no-ajax, download, dış site, mailto/#.
    document.addEventListener('click', function (e) {
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        var a = e.target.closest && e.target.closest('a');
        if (!a || a.hasAttribute('data-no-ajax') || a.hasAttribute('download') || a.target === '_blank') return;
        if (a.protocol !== 'http:' && a.protocol !== 'https:') return;   // mailto/tel vb.
        if (a.origin !== location.origin) return;                        // dış site
        var href = a.getAttribute('href');
        if (!href || href.charAt(0) === '#') return;                     // sayfa-içi çapa
        e.preventDefault();
        go(a.href, { headers: { 'X-Requested-With': 'fetch' } }, false, true);
    });

    window.addEventListener('popstate', function () {
        go(location.href, { headers: { 'X-Requested-With': 'fetch' } }, false, false);
    });
})();
