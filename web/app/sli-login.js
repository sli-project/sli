(() => {
  "use strict";

  // Standalone copy of pages:login in frontend/src/i18n/{ru,en}.ts.
  // login.test.ts checks the rendered translations against those dictionaries.
  const dictionaries = {
    "ru": {
      "login.error.authenticationRequired": "Необходимо войти в систему.",
      "login.error.origin": "Запрос входа отклонён. Откройте страницу входа с адреса сервера.",
      "login.documentTitle": "SLI — Вход в систему",
      "login.aria.authorization": "Авторизация SLI",
      "login.aria.features": "Возможности SLI",
      "login.feature.visibility": "Видимость",
      "login.feature.visibility.description": "Полная картина событий",
      "login.feature.intelligence": "Интеллект",
      "login.feature.intelligence.description": "Аналитика и корреляция",
      "login.feature.protection": "Защита",
      "login.feature.protection.description": "Безопасность и соответствие",
      "login.welcome": "Добро пожаловать",
      "login.title": "Вход в систему",
      "login.description": "Введите данные учётной записи администратора или сотрудника.",
      "login.username": "Логин",
      "login.username.placeholder": "Введите логин",
      "login.password": "Пароль",
      "login.password.placeholder": "Введите пароль",
      "login.password.show": "Показать пароль",
      "login.password.hide": "Скрыть пароль",
      "login.remember": "Запомнить меня",
      "login.recovery.title": "Аварийный вход владельца",
      "login.recovery.description": "Получите одноразовый код у администратора консоли сервера. Код действует 10 минут; пароль также обязателен.",
      "login.recovery.code": "Код восстановления",
      "login.submit": "Войти",
      "login.busy": "Проверяем данные…",
      "login.transport.tls": "Подключение защищено с использованием шифрования TLS 1.2+.",
      "login.transport.http": "Локальная HTTP-копия предназначена только для проверки. Рабочий вход использует HTTPS.",
      "login.language": "Язык",
      "login.language.ru": "Русский",
      "login.language.en": "English",
      "login.error.required": "Введите логин и пароль.",
      "login.error.credentials": "Не удалось войти. Проверьте логин и пароль.",
      "login.error.retryAfter": "Слишком много попыток входа. Повторите через {seconds} сек.",
      "login.error.locked": "Слишком много попыток входа. Повторите позже.",
      "login.error.https": "Вход разрешён только через защищённое HTTPS-соединение.",
      "login.error.disabled": "Авторизация на сервере отключена.",
      "login.error.unavailable": "Сервис входа временно недоступен. Повторите попытку позже.",
      "login.error.generic": "Не удалось выполнить вход. Повторите попытку.",
      "login.error.timeout": "Сервер не ответил вовремя. Проверьте соединение и повторите попытку."
    },
    "en": {
      "login.error.authenticationRequired": "Sign in to continue.",
      "login.error.origin": "Sign-in request rejected. Open the sign-in page from the server address.",
      "login.documentTitle": "SLI — Sign in",
      "login.aria.authorization": "SLI sign in",
      "login.aria.features": "SLI features",
      "login.feature.visibility": "Visibility",
      "login.feature.visibility.description": "A complete view of events",
      "login.feature.intelligence": "Intelligence",
      "login.feature.intelligence.description": "Analytics and correlation",
      "login.feature.protection": "Protection",
      "login.feature.protection.description": "Security and compliance",
      "login.welcome": "Welcome",
      "login.title": "Sign in",
      "login.description": "Enter your administrator or employee account credentials.",
      "login.username": "Username",
      "login.username.placeholder": "Enter your username",
      "login.password": "Password",
      "login.password.placeholder": "Enter your password",
      "login.password.show": "Show password",
      "login.password.hide": "Hide password",
      "login.remember": "Remember me",
      "login.recovery.title": "Owner emergency sign-in",
      "login.recovery.description": "Obtain a single-use code from the server console administrator. It expires in 10 minutes; your password is also required.",
      "login.recovery.code": "Recovery code",
      "login.submit": "Sign in",
      "login.busy": "Checking credentials…",
      "login.transport.tls": "The connection is secured with TLS 1.2+ encryption.",
      "login.transport.http": "The local HTTP copy is for testing only. Production sign-in uses HTTPS.",
      "login.language": "Language",
      "login.language.ru": "Русский",
      "login.language.en": "English",
      "login.error.required": "Enter your username and password.",
      "login.error.credentials": "Sign-in failed. Check your username and password.",
      "login.error.retryAfter": "Too many sign-in attempts. Try again in {seconds} seconds.",
      "login.error.locked": "Too many sign-in attempts. Try again later.",
      "login.error.https": "Sign-in requires a secure HTTPS connection.",
      "login.error.disabled": "Authentication is disabled on the server.",
      "login.error.unavailable": "The sign-in service is temporarily unavailable. Try again later.",
      "login.error.generic": "Sign-in failed. Try again.",
      "login.error.timeout": "The server did not respond in time. Check your connection and try again."
    }
  };

  const form = document.querySelector("#sli-login-form");
  const username = document.querySelector("#username");
  const password = document.querySelector("#password");
  const recoveryCode = document.querySelector("#recovery-code");
  const remember = form?.elements.namedItem("remember");
  const toggle = document.querySelector(".sli-password-toggle");
  const submit = document.querySelector("#sli-login-submit");
  const submitLabel = submit?.querySelector("span");
  const message = document.querySelector("#sli-login-message");
  const transportNote = document.querySelector("#sli-transport-note");
  const localeSelect = document.querySelector("#sli-locale");
  const readPreference = (key) => {
    try { return window.localStorage.getItem(key); } catch { return null; }
  };
  const storedLocale = readPreference("sli.locale");
  let locale = storedLocale === "en" ? "en" : "ru";
  const translate = (key, params = {}) => dictionaries[locale][key].replace(/\{(\w+)\}/g,
    (match, name) => name in params ? String(params[name]) : match);

  if (
    !(form instanceof HTMLFormElement) ||
    !(username instanceof HTMLInputElement) ||
    !(password instanceof HTMLInputElement) ||
    !(remember instanceof HTMLInputElement) ||
    !(toggle instanceof HTMLButtonElement) ||
    !(submit instanceof HTMLButtonElement) ||
    !submitLabel ||
    !message
  ) {
    return;
  }

  let messageTranslation = null;
  const messageCopy = (key, params = {}) => {
    messageTranslation = { key, params };
    return translate(key, params);
  };
  const setMessage = (text = "", state = "") => {
    message.textContent = text;
    if (!text) messageTranslation = null;
    if (state) {
      message.dataset.state = state;
    } else {
      delete message.dataset.state;
    }
  };

  const setBusy = (busy) => {
    form.setAttribute("aria-busy", String(busy));
    submit.disabled = busy;
    submitLabel.textContent = translate(busy ? "login.busy" : "login.submit");
  };

  const applyLocale = () => {
    document.documentElement.lang = locale;
    for (const element of document.querySelectorAll("[data-i18n]")) {
      element.textContent = translate(element.dataset.i18n);
    }
    for (const element of document.querySelectorAll("[data-i18n-placeholder]")) {
      element.setAttribute("placeholder", translate(element.dataset.i18nPlaceholder));
    }
    for (const element of document.querySelectorAll("[data-i18n-aria-label]")) {
      element.setAttribute("aria-label", translate(element.dataset.i18nAriaLabel));
    }
    toggle.setAttribute("aria-label", translate(password.type === "password" ? "login.password.show" : "login.password.hide"));
    setBusy(submit.disabled);
    if (messageTranslation) message.textContent = translate(messageTranslation.key, messageTranslation.params);
    if (transportNote) transportNote.textContent = translate(window.location.protocol !== "https:" ? "login.transport.http" : "login.transport.tls");
    if (localeSelect) localeSelect.value = locale;
  };
  localeSelect?.addEventListener("change", () => {
    locale = localeSelect.value;
    try { window.localStorage.setItem("sli.locale", locale); } catch { /* Storage may be blocked. */ }
    applyLocale();
  });
  applyLocale();

  const safeDestination = (rawValue) => {
    const fallback = "/";
    if (!rawValue) return fallback;

    try {
      const target = new URL(rawValue, window.location.origin);
      if (target.origin !== window.location.origin || target.pathname === "/login") {
        return fallback;
      }
      return `${target.pathname}${target.search}${target.hash}`;
    } catch {
      return fallback;
    }
  };

  const errorMessage = (payload, status) => {
    const envelope = payload?.message;
    if (envelope && typeof envelope.code === "string" && envelope.code.startsWith("login.error.")
      && Object.hasOwn(dictionaries[locale], envelope.code)) {
      const params = envelope.params && typeof envelope.params === "object" ? envelope.params : {};
      return messageCopy(envelope.code, params);
    }
    const code = payload && typeof payload.error === "string" ? payload.error : "";
    if (code === "invalid_credentials" || status === 401) {
      return messageCopy("login.error.credentials");
    }
    if (code === "login_temporarily_locked" || status === 429) {
      const retryAfter = Number(payload?.retry_after_seconds);
      return Number.isFinite(retryAfter) && retryAfter > 0
        ? messageCopy("login.error.retryAfter", { seconds: Math.ceil(retryAfter) })
        : messageCopy("login.error.locked");
    }
    if (code === "secure_transport_required") {
      return messageCopy("login.error.https");
    }
    if (code === "authentication_not_enabled") {
      return messageCopy("login.error.disabled");
    }
    if (status >= 500) {
      return messageCopy("login.error.unavailable");
    }
    return messageCopy("login.error.generic");
  };

  toggle.addEventListener("click", () => {
    const makeVisible = password.type === "password";
    password.type = makeVisible ? "text" : "password";
    toggle.setAttribute("aria-pressed", String(makeVisible));
    toggle.setAttribute("aria-label", translate(makeVisible ? "login.password.hide" : "login.password.show"));
    password.focus();
  });

  username.addEventListener("input", () => setMessage());
  password.addEventListener("input", () => setMessage());

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setMessage();

    const cleanUsername = username.value.trim();
    if (!cleanUsername || !password.value) {
      setMessage(messageCopy("login.error.required"));
      (!cleanUsername ? username : password).focus();
      return;
    }

    setBusy(true);
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15_000);

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Accept": "application/json",
          "Accept-Language": locale,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: cleanUsername,
          password: password.value,
          remember: remember.checked,
          ...(recoveryCode?.value.trim() ? { recovery_code: recoveryCode.value.trim() } : {}),
        }),
        signal: controller.signal,
      });

      let payload = {};
      try {
        payload = await response.json();
      } catch {
        payload = {};
      }

      if (!response.ok) {
        throw new Error(errorMessage(payload, response.status));
      }

      const requested = new URLSearchParams(window.location.search).get("next");
      window.location.assign(safeDestination(requested));
    } catch (error) {
      const copy = error instanceof DOMException && error.name === "AbortError"
        ? messageCopy("login.error.timeout")
        : messageTranslation
          ? translate(messageTranslation.key, messageTranslation.params)
          : messageCopy("login.error.generic");
      setMessage(copy);
    } finally {
      if (recoveryCode) recoveryCode.value = "";
      window.clearTimeout(timeout);
      setBusy(false);
    }
  });
})();
