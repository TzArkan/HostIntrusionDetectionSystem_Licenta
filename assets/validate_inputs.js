/* validate_inputs.js - Sticky Errors + Curatenie la navigare intre sectiuni */

(function () {
    var REGEX_DOAR_IP    = /[^0-9.]/g;
    var REGEX_DOAR_CIFRE = /[^0-9]/g;
    var REGEX_TS         = /[^0-9\s\-:]/g;

    var FILTRE = [
        { suffix: "src-ip",   filtru: REGEX_DOAR_IP,    valid: /^(\d{1,3}\.){3}\d{1,3}$/,  eroare: "Format IP: ex. 192.168.1.10" },
        { suffix: "dst-ip",   filtru: REGEX_DOAR_IP,    valid: /^(\d{1,3}\.){3}\d{1,3}$/,  eroare: "Format IP: ex. 8.8.8.8" },
        { suffix: "f-ip",     filtru: REGEX_DOAR_IP,    valid: /^(\d{1,3}\.){3}\d{1,3}$/,  eroare: "Format IP: ex. 192.168.1.10" },
        { suffix: "ip1",      filtru: null,             valid: /^(\d{1,3}\.){3}\d{1,3}$/,  eroare: "Format IP invalid" },
        { suffix: "src-port", filtru: REGEX_DOAR_CIFRE, valid: /^\d{1,5}$/,                eroare: "Port: cifre 1-65535" },
        { suffix: "dst-port", filtru: REGEX_DOAR_CIFRE, valid: /^\d{1,5}$/,                eroare: "Port: cifre 1-65535" },
        { suffix: "f-src-port", filtru: REGEX_DOAR_CIFRE, valid: /^\d{1,5}$/,              eroare: "Port: cifre 1-65535" },
        { suffix: "f-dst-port", filtru: REGEX_DOAR_CIFRE, valid: /^\d{1,5}$/,              eroare: "Port: cifre 1-65535" },
        { suffix: "ts-start", filtru: REGEX_TS,         valid: /^(\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}(:\d{2})?$/, eroare: "Format: YYYY-MM-DD HH:MM:SS" },
        { suffix: "ts-end",   filtru: REGEX_TS,         valid: /^(\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}(:\d{2})?$/, eroare: "Format: YYYY-MM-DD HH:MM:SS" },
        { suffix: "f-ts-start", filtru: REGEX_TS,       valid: /^(\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}(:\d{2})?$/, eroare: "Format: YYYY-MM-DD HH:MM:SS" },
        { suffix: "f-ts-end",   filtru: REGEX_TS,       valid: /^(\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}(:\d{2})?$/, eroare: "Format: YYYY-MM-DD HH:MM:SS" },
        { suffix: "r-port",   filtru: REGEX_DOAR_CIFRE, valid: /^\d{1,5}$/,                eroare: "Port: cifre 1-65535" },
        { suffix: "r-flags",  filtru: /[^SAFRPUsafrpu]/g, valid: /^[SsAaFfRrPpUu]+$/,     eroare: "Flags permise: S A F R P U" },
        { suffix: "fim-cale", filtru: null,             valid: /^([A-Za-z]:\\|\/)/,        eroare: "Cale completă: ex. C:\\Windows\\..." },
        { suffix: "f-portscan", filtru: REGEX_DOAR_CIFRE, valid: /^\d{1,5}$/,              eroare: "Port: cifre 1-65535" },
        { suffix: "f-min-len", filtru: null, valid: /^\d+$/, eroare: "Doar cifre pozitive" },
        { suffix: "f-max-len", filtru: null, valid: /^\d+$/, eroare: "Doar cifre pozitive" },
    ];

    function gaseste_regula(id_input) {
        for (var i = 0; i < FILTRE.length; i++) {
            if (id_input.indexOf(FILTRE[i].suffix) !== -1) return FILTRE[i];
        }
        return null;
    }

    // NOU: Registru global în care reținem absolut toate popup-urile generate
    var _toate_popupurile = []; 

    function _obtine_popup(input_el) {
        if (!input_el._popup_el) {
            var p = document.createElement('div');
            p.style.cssText =
                'position:fixed; background:#1e1a10; color:#fbbf24; border:1px solid #92400e; border-radius:5px; padding:5px 12px; font-size:11px; z-index:9999; white-space:nowrap; display:none; box-shadow:0 4px 16px rgba(0,0,0,.65); pointer-events:none; transition:opacity .1s;';
            document.body.appendChild(p);
            input_el._popup_el = p;
            
            // Când un popup e creat, îl adăugăm în lista de curățenie
            _toate_popupurile.push({ input: input_el, popup: p });
        }
        return input_el._popup_el;
    }

    function afiseaza_eroare(input_el, mesaj) {
        var p = _obtine_popup(input_el);

        if (!mesaj) {
            p.style.display = 'none';
            input_el.style.borderColor = '';
            return;
        }
        
        var rect = input_el.getBoundingClientRect();
        p.textContent   = mesaj;
        p.style.left    = rect.left + 'px';
        p.style.top     = (rect.bottom + 4) + 'px';
        p.style.display = 'block';
    }

    /* Declanșează validarea pe butonul "Cauta" + Ascunde la click în meniu */
    document.addEventListener('click', function (e) {
        
        // Dacă utilizatorul a dat click pe sidebar/meniu, ascundem fortat toate erorile
        var click_pe_meniu = e.target.closest('#app-sidebar');
        if (click_pe_meniu) {
            _toate_popupurile.forEach(function(item) {
                item.popup.style.display = 'none';
            });
            return;
        }

        // Declanșează validarea doar la apăsarea butonului "Caută"
        if (e.target && e.target.tagName === 'BUTTON' && e.target.textContent.includes('Cauta')) {
            var inputs = document.querySelectorAll('input[data-hids-validat="1"]');
            inputs.forEach(function (inp) {
                var regula = gaseste_regula(inp.id || '');
                if (regula) {
                    var val = inp.value.trim();
                    if (val !== '' && !regula.valid.test(val)) {
                        afiseaza_eroare(inp, '⚠ ' + regula.eroare);
                        inp.style.borderColor = '#92400e';
                    } else {
                        afiseaza_eroare(inp, ''); 
                    }
                }
            });
        }
    });

    document.addEventListener('scroll', function () {
        var inputs = document.querySelectorAll('input[data-hids-validat="1"]');
        inputs.forEach(function(inp) {
            if (inp._popup_el && inp._popup_el.style.display === 'block') {
                var rect = inp.getBoundingClientRect();
                inp._popup_el.style.left = rect.left + 'px';
                inp._popup_el.style.top  = (rect.bottom + 4) + 'px';
            }
        });
    }, true);

    function ataseaza_validare(input_el, regula) {
        input_el.addEventListener('input', function () {
            if (regula.filtru) {
                var pozitie = this.selectionStart;
                var val_nou = this.value.replace(regula.filtru, '');
                if (val_nou !== this.value) {
                    this.value = val_nou;
                    this.setSelectionRange(pozitie - 1, pozitie - 1);
                    var ev = new Event('input', { bubbles: true });
                    this.dispatchEvent(ev);
                }
            }
        });

        // Ascunde eroarea CÂND DAI CLICK în căsuță pentru a o corecta
        input_el.addEventListener('focus', function () {
            afiseaza_eroare(this, '');
        });
    }

    var observer = new MutationObserver(function (mutations) {
        
        // NOU: GARBAGE COLLECTION
        // La fiecare schimbare pe ecran, căutăm popup-urile rămase active (block).
        // Dacă input-ul lor a fost distrus (nu mai e in document.body), ascundem popup-ul.
        _toate_popupurile.forEach(function(item) {
            if (item.popup.style.display === 'block' && !document.body.contains(item.input)) {
                item.popup.style.display = 'none';
            }
        });

        mutations.forEach(function (m) {
            m.addedNodes.forEach(function (nod) {
                if (nod.nodeType !== 1) return;
                var inputs = nod.querySelectorAll
                    ? nod.querySelectorAll('input[type="text"], input:not([type])')
                    : [];
                inputs.forEach(function (inp_el) {
                    if (inp_el.dataset.hidsValidat) return;
                    inp_el.dataset.hidsValidat = '1';
                    var regula = gaseste_regula(inp_el.id || '');
                    if (regula) ataseaza_validare(inp_el, regula);
                });
            });
        });
    });

    document.addEventListener('DOMContentLoaded', function () {
        observer.observe(document.body, { childList: true, subtree: true });
    });

})();