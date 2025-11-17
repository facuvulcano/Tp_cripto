# Sistema de Login Seguro

Implementación de referencia para un backend de autenticación centrado en controles de seguridad modernos. El servicio expone endpoints REST mínimos para registro, login, rotación de tokens, cierre de sesión y cambio de contraseña, respaldados por políticas de privacidad, auditoría y evidencias automatizadas.

## Características principales
- **Hashing Argon2id** con parámetros reforzados (`t=3`, `m=65536`, `p=2`) y validaciones estrictas de complejidad de contraseña.
- **JWT de doble capa**: access tokens de 5 minutos y refresh tokens de 7 días con rotación obligatoria, revocación persistida y límite absoluto de sesión.
- **Cookies seguras** (`HttpOnly`, `Secure`, `SameSite`) más token CSRF adicional para operaciones sensibles.
- **Bloqueos inteligentes**: contador por cuenta, rate limiting por IP y revocación masiva automática en cambios de contraseña.
- **Auditoría y trazabilidad** de eventos críticos (logins, refresh, fallos, logout, cambios de contraseña).
- **Pruebas automatizadas** enfocadas en los flujos críticos de autenticación y scripts de soporte para ejecución y generación de evidencias.

## Requisitos
- Python 3.12+
- SQLite (incluido) u otra base de datos compatible con SQLAlchemy.

Instala las dependencias:

```bash
pip install -r requirements.txt
```

## Uso

### Servidor de desarrollo

```bash
./scripts/run_dev.sh
```

Variables clave (se pueden definir antes de ejecutar el script):

| Variable | Descripción |
| --- | --- |
| `DATABASE_URL` | URL de conexión SQLAlchemy (por defecto `sqlite:///./data/app.db`). |
| `JWT_SECRET_KEY` | Clave HS256 de alta entropía para firmar los JWT. |
| `AUTH_COOKIE_SECURE` | Define si las cookies requieren HTTPS (habilitar en producción). |

### Endpoints

| Método | Ruta | Descripción |
| --- | --- | --- |
| `POST /auth/register` | Alta de usuario (email único + nombre opcional). |
| `POST /auth/login` | Valida credenciales, entrega cookies y registra auditoría. |
| `POST /auth/refresh` | Valida refresh token, lo rota y revoca el anterior. |
| `POST /auth/logout` | Revoca el refresh token activo y limpia cookies (requiere CSRF). |
| `POST /auth/change-password` | Verifica contraseña actual, aplica nueva y revoca todas las sesiones. |
| `GET /auth/me` | Devuelve los datos básicos del usuario autenticado. |
| `GET /auth/logs` | Últimos eventos de auditoría asociados al usuario. |

### Frontend interactivo

El backend expone un frontend estático básico accesible en `http://localhost:8000/ui` (o el puerto que estés usando). Incluye formularios para registro, login, refresh, logout, cambio de contraseña, `/auth/me` y `/auth/logs`. Todas las peticiones se realizan con `fetch` y `credentials: 'include'`, por lo que es importante acceder al frontend desde el mismo origen donde corre el backend.

### Pruebas automatizadas

```bash
./scripts/run_tests.sh
```

El archivo `docs/evidence/test_results.txt` almacena la salida más reciente de `pytest`. Las pruebas trabajan directamente sobre el servicio de autenticación (`AuthService`) para validar:

1. Registro y login con emisión de cookies `HttpOnly`.
2. Rotación de refresh tokens y detección de reuso.
3. Cambio de contraseña con revocación total de sesiones.
4. Bloqueo de cuentas tras múltiples fallos consecutivos.

### Evidencias adicionales
- `docs/evidence/test_results.txt`: ejecución documentada de las pruebas.
- `docs/evidence/captura_login.png`: captura/diagrama sintético del flujo seguro.

## Arquitectura y decisiones
- **Separación de capas**: controladores (FastAPI), servicios (`AuthService`), utilidades criptográficas y modelos SQLAlchemy.
- **Sesiones persistidas**: la tabla `refresh_tokens` registra `jti`, expiraciones relativas y absolutas, IP y navegador, habilitando revocaciones granulares.
- **Auditoría**: la tabla `auth_logs` conserva evento, IP, user-agent y metadatos mínimos para análisis de incidentes.
- **Protecciones activas**: CSRF con cookie + cabecera fuera de las cookies `HttpOnly`, respuesta genérica ante credenciales inválidas, y política de minimización de datos (solo email, nombre y hashes).

## Documentación
La especificación formal del trabajo se encuentra en `docs/latex/Sistema_Login_Seguro.tex`, lista para compilarse con `pdflatex`.

## Próximos pasos sugeridos
- Añadir flujo de recuperación de contraseña con token de un solo uso.
- Integrar un almacén seguro de secretos (HashiCorp Vault, AWS Secrets Manager, etc.).
- Automatizar despliegues y escaneos SAST/DAST para fortalecer el ciclo CI/CD.
