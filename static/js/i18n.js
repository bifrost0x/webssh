// Dictionaries live in static/js/i18n/<lang>.js and register themselves via
// i18n.registerLocales(). Pages load English plus the active language only.
const translations = { en: {}, vi: {}, de: {}, fr: {}, es: {}, zh: {} };

const BrowserPreferences = {
    get(key, fallback = null) {
        try {
            const value = window.localStorage?.getItem(key);
            return typeof value === 'string' && value ? value : fallback;
        } catch {
            return fallback;
        }
    },

    set(key, value) {
        try {
            window.localStorage?.setItem(key, String(value));
            return true;
        } catch {
            return false;
        }
    }
};

const storedLanguage = BrowserPreferences.get('language', 'en');
// Only dictionaries shipped inside this file (the generated authentication
// bundle) count as loaded here; everything else is registered later.
const loadedLocales = new Set(Object.keys(translations).filter(lang => Object.keys(translations[lang]).length > 0));
const pendingLocales = new Map();
let requestedLanguage = null;
let pendingSwitch = null;

function readLocaleUrls() {
    const urls = {};
    let declared = {};
    try {
        declared = JSON.parse(document.currentScript?.dataset?.locales || '{}');
    } catch {
        declared = {};
    }
    for (const lang of Object.keys(translations)) {
        const url = sameOriginLocaleUrl(declared?.[lang], lang);
        if (url) urls[lang] = url;
    }
    return urls;
}

// Accepts only a server-rendered, versioned path to this language's file on
// the same origin. The application root may contain any valid path
// characters; the returned value is the parser's percent-encoded form, so it
// cannot break out of the script tag it is written into.
function sameOriginLocaleUrl(url, lang) {
    if (typeof url !== 'string' || !url.startsWith('/') || url.startsWith('//')) return null;
    const base = 'http://webssh.invalid';
    let parsed;
    try {
        parsed = new URL(url, base);
    } catch {
        return null;
    }
    if (parsed.origin !== base || parsed.username || parsed.password || parsed.hash) return null;
    if (!parsed.pathname.endsWith(`/${lang}.js`) || !/^\?v=[0-9a-f]{16}$/.test(parsed.search)) return null;
    return parsed.pathname + parsed.search;
}

const localeUrls = readLocaleUrls();
// A stalled request must not leave a language switch pending forever.
const LOCALE_LOAD_TIMEOUT_MS = 15000;

function loadLocale(lang) {
    if (loadedLocales.has(lang)) return Promise.resolve();
    if (pendingLocales.has(lang)) return pendingLocales.get(lang);
    const url = localeUrls[lang];
    if (!url || typeof document.createElement !== 'function') {
        return Promise.reject(new Error(`No translation file for ${lang}`));
    }
    const pending = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = url;
        script.async = true;
        const timer = setTimeout(() => {
            script.onload = null;
            script.onerror = null;
            script.remove();
            reject(new Error(`Translation file for ${lang} timed out`));
        }, LOCALE_LOAD_TIMEOUT_MS);
        script.onload = () => {
            clearTimeout(timer);
            if (loadedLocales.has(lang)) resolve();
            else reject(new Error(`Translation file for ${lang} did not register`));
        };
        script.onerror = () => {
            clearTimeout(timer);
            script.remove();
            reject(new Error(`Translation file for ${lang} could not be loaded`));
        };
        (document.head || document.documentElement).appendChild(script);
    }).finally(() => pendingLocales.delete(lang));
    pendingLocales.set(lang, pending);
    return pending;
}

const i18n = {
    currentLang: Object.hasOwn(translations, storedLanguage) ? storedLanguage : 'en',

    registerLocales(bundle) {
        if (!bundle || typeof bundle !== 'object') return false;
        for (const [lang, values] of Object.entries(bundle)) {
            if (!Object.hasOwn(translations, lang) || !values || typeof values !== 'object') continue;
            for (const [key, value] of Object.entries(values)) {
                // Feature bundles may have registered first; their entries win,
                // matching the order in which pages load them.
                if (typeof value === 'string' && !Object.hasOwn(translations[lang], key)
                    && !['__proto__', 'constructor', 'prototype'].includes(key)) {
                    translations[lang][key] = value;
                }
            }
            loadedLocales.add(lang);
        }
        return true;
    },

    addTranslations(lang, values) {
        if (!Object.hasOwn(translations, lang) || !values || typeof values !== 'object' || Array.isArray(values)) return false;
        for (const [key, value] of Object.entries(values)) {
            if (typeof value === 'string' && !['__proto__', 'constructor', 'prototype'].includes(key)) translations[lang][key] = value;
        }
        return true;
    },

    t(key) {
        const activeTranslations = translations[this.currentLang] || translations.en;
        return activeTranslations[key] || translations.en[key] || key;
    },

    isLocaleLoaded(lang) {
        return loadedLocales.has(lang);
    },

    loadLocale(lang) {
        return Object.hasOwn(translations, lang) ? loadLocale(lang) : Promise.reject(new Error(`Unsupported language ${lang}`));
    },

    // Resolves to true once the language is active. A loaded language is
    // applied synchronously; otherwise its file is fetched first. When switches
    // overlap, only the most recently requested language is applied.
    setLanguage(lang) {
        if (!Object.hasOwn(translations, lang)) return Promise.resolve(false);
        requestedLanguage = lang;
        const apply = () => {
            if (requestedLanguage !== lang) return false;
            this.currentLang = lang;
            BrowserPreferences.set('language', lang);
            this.updatePageText();

            window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));
            return true;
        };
        if (loadedLocales.has(lang)) return Promise.resolve(apply());
        if (pendingSwitch?.lang === lang) return pendingSwitch.promise;
        const promise = loadLocale(lang).then(apply, () => false);
        pendingSwitch = { lang, promise };
        promise.finally(() => {
            if (pendingSwitch?.promise === promise) pendingSwitch = null;
        });
        return promise;
    },

    getLanguage() {
        return this.currentLang;
    },

    getLanguages() {
        return [
            { code: 'en', name: 'English', flag: 'EN' },
            { code: 'vi', name: 'Tiếng Việt', flag: 'VI' },
            { code: 'de', name: 'Deutsch', flag: 'DE' },
            { code: 'fr', name: 'Français', flag: 'FR' },
            { code: 'es', name: 'Español', flag: 'ES' },
            { code: 'zh', name: '中文', flag: 'ZH' }
        ];
    },

    updatePageText() {
        document.documentElement.lang = this.currentLang;

        document.querySelectorAll('[data-i18n]').forEach(element => {
            const key = element.getAttribute('data-i18n');
            const translation = this.t(key);

            if (element.tagName === 'INPUT' && element.type !== 'submit') {
                element.placeholder = translation;
            } else {
                element.textContent = translation;
            }
        });

        document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
            const key = element.getAttribute('data-i18n-placeholder');
            element.placeholder = this.t(key);
        });

        document.querySelectorAll('[data-i18n-title]').forEach(element => {
            const key = element.getAttribute('data-i18n-title');
            element.title = this.t(key);
        });

        document.querySelectorAll('[data-i18n-label]').forEach(element => {
            const key = element.getAttribute('data-i18n-label');
            element.label = this.t(key);
        });

        document.querySelectorAll('[data-i18n-aria-label]').forEach(element => {
            const key = element.getAttribute('data-i18n-aria-label');
            element.setAttribute('aria-label', this.t(key));
        });

        document.querySelectorAll('[data-i18n-alt]').forEach(element => {
            const key = element.getAttribute('data-i18n-alt');
            element.alt = this.t(key);
        });

        if (!document.querySelector('title[data-i18n]') && document.title.includes('SSH Terminal')) {
            document.title = this.t('app.title');
        }
    }
};

window.BrowserPreferences = BrowserPreferences;
window.i18n = i18n;

// Scripts after this one call i18n.t() while the page is parsed, so the active
// dictionary is inserted as a parser-blocking same-origin script right here.
// Pages always load English themselves; later switches load asynchronously.
if (i18n.currentLang !== 'en' && !loadedLocales.has(i18n.currentLang) && localeUrls[i18n.currentLang]
    && document.readyState === 'loading' && typeof document.write === 'function') {
    document.write(`<script src="${localeUrls[i18n.currentLang]}"></script>`);
}

document.addEventListener('DOMContentLoaded', () => {
    i18n.updatePageText();
});
