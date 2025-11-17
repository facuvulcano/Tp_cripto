const output = document.getElementById("output");

const endpoints = {
  register: "/auth/register",
  login: "/auth/login",
  refresh: "/auth/refresh",
  logout: "/auth/logout",
  changePassword: "/auth/change-password",
  me: "/auth/me",
  logs: "/auth/logs",
};

const settings = {
  csrfHeader: "X-CSRF-Token",
  csrfCookie: "csrf_token",
};

function render(message, payload, isError = false) {
  const content = {
    timestamp: new Date().toISOString(),
    message,
    payload,
  };
  output.textContent = JSON.stringify(content, null, 2);
  output.style.borderColor = isError ? "var(--danger)" : "rgba(255,255,255,0.2)";
}

function readCookie(name) {
  const value = document.cookie
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${name}=`));
  return value ? decodeURIComponent(value.split("=")[1]) : null;
}

async function apiFetch(path, { method = "GET", body, csrf = false } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (csrf) {
    const csrfToken = readCookie(settings.csrfCookie);
    if (!csrfToken) {
      throw new Error("No se encontró la cookie CSRF. Inicia sesión primero.");
    }
    headers[settings.csrfHeader] = csrfToken;
  }

  const response = await fetch(path, {
    method,
    headers,
    credentials: "include",
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data?.detail || response.statusText;
    throw new Error(message);
  }
  return data;
}

function extractPayload(form) {
  const formData = new FormData(form);
  return Object.fromEntries(formData.entries());
}

function setupForms() {
  document.getElementById("register-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = extractPayload(event.target);
    if (!payload.name) delete payload.name;
    try {
      const data = await apiFetch(endpoints.register, { method: "POST", body: payload });
      render("Usuario registrado", data);
      event.target.reset();
    } catch (error) {
      render("Error al registrar", error.message, true);
    }
  });

  document.getElementById("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = extractPayload(event.target);
    try {
      const data = await apiFetch(endpoints.login, { method: "POST", body: payload });
      render("Login exitoso", data);
      event.target.reset();
    } catch (error) {
      render("Error al iniciar sesión", error.message, true);
    }
  });

  document.getElementById("refresh-btn").addEventListener("click", async () => {
    try {
      const data = await apiFetch(endpoints.refresh, { method: "POST" });
      render("Tokens rotados", data);
    } catch (error) {
      render("Error al refrescar", error.message, true);
    }
  });

  document.getElementById("logout-btn").addEventListener("click", async () => {
    try {
      const data = await apiFetch(endpoints.logout, { method: "POST", csrf: true });
      render("Sesión cerrada", data);
    } catch (error) {
      render("Error al cerrar sesión", error.message, true);
    }
  });

  document.getElementById("password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = extractPayload(event.target);
    try {
      const data = await apiFetch(endpoints.changePassword, {
        method: "POST",
        body: payload,
        csrf: true,
      });
      render("Contraseña actualizada", data);
      event.target.reset();
    } catch (error) {
      render("Error al cambiar contraseña", error.message, true);
    }
  });

  document.getElementById("me-btn").addEventListener("click", async () => {
    try {
      const data = await apiFetch(endpoints.me);
      render("Perfil", data);
    } catch (error) {
      render("Error al obtener perfil", error.message, true);
    }
  });

  document.getElementById("logs-btn").addEventListener("click", async () => {
    try {
      const data = await apiFetch(endpoints.logs);
      render("Logs", data);
    } catch (error) {
      render("Error al obtener logs", error.message, true);
    }
  });
}

setupForms();
