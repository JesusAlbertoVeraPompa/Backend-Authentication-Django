# 🔐 Django Auth API

API REST de autenticación y gestión de usuarios construida con Django + Django REST Framework.

---

## 📁 Estructura del proyecto

```
Autenticacion/
├── apps/
│   ├── accounts/               # Autenticación, modelo User, verificación SMS
│   │   ├── management/
│   │   │   └── commands/
│   │   │       ├── seed_roles.py      # Crea grupos Admin/Personal/Usuario
│   │   │       └── create_admin.py    # Crea superusuario desde env vars
│   │   ├── migrations/
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py           # User, VerificationCode, PasswordResetToken
│   │   ├── serializers.py
│   │   ├── signals.py          # Auto-asigna grupo al registrar usuario
│   │   ├── urls.py
│   │   └── views.py
│   ├── core/                   # Utilidades compartidas
│   │   ├── decorators.py       # @admin_required, @personal_required
│   │   ├── exceptions.py       # Handler global de excepciones DRF
│   │   ├── middleware.py       # RoleMiddleware
│   │   ├── pagination.py       # Paginación con formato estándar
│   │   ├── permissions.py      # IsAdmin, IsPersonal, IsOwnerOrAdmin
│   │   ├── responses.py        # success_response / error_response
│   │   └── utils.py            # SMS, email, generación de códigos
│   └── users/                  # Gestión CRUD de usuarios
│       ├── filters.py
│       ├── serializers.py
│       ├── urls.py
│       └── views.py
├── config/
│   ├── settings/
│   │   ├── base.py             # Configuración compartida
│   │   ├── development.py      # Solo desarrollo
│   │   └── production.py       # Producción (Render/Heroku)
│   ├── urls.py
│   └── wsgi.py
├── tests/
│   ├── conftest.py             # Fixtures compartidos (usuarios, clientes)
│   ├── accounts/
│   │   ├── test_register.py
│   │   ├── test_login.py
│   │   ├── test_verification.py
│   │   ├── test_social_login.py
│   │   └── test_password.py
│   └── users/
│       └── test_users.py
├── .env.example
├── .gitignore
├── build.sh                    # Script de build para Render
├── manage.py
├── Procfile
├── pytest.ini
└── requirements.txt
```

---

## ⚙️ Instalación local

### 1. Prerrequisitos

- Python 3.11+
- MySQL 8.0+
- Git

### 2. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/django-auth-api.git
cd django-auth-api
```

### 3. Crear entorno virtual

```bash
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
```

### 4. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 5. Crear base de datos MySQL

```sql
CREATE DATABASE django_auth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'django_user'@'localhost' IDENTIFIED BY 'tu_password';
GRANT ALL PRIVILEGES ON django_auth_db.* TO 'django_user'@'localhost';
FLUSH PRIVILEGES;
```

### 6. Configurar variables de entorno

```bash
cp .env.example .env
```

Edita `.env` con tus valores (ver sección [Variables de entorno](#variables-de-entorno)).

### 7. Ejecutar migraciones

```bash
python manage.py migrate
```

### 8. Crear grupos de roles

```bash
python manage.py seed_roles
```

### 9. Crear superusuario

```bash
python manage.py createsuperuser
```

### 10. Iniciar servidor

```bash
python manage.py runserver
```

API disponible en: `http://localhost:8000/api/v1/`

---

## 🔑 Variables de entorno

Copia `.env.example` a `.env` y completa los siguientes valores:

| Variable | Descripción | Ejemplo |
|---|---|---|
| `SECRET_KEY` | Clave secreta Django | `django-insecure-...` |
| `DEBUG` | Modo debug | `True` / `False` |
| `ALLOWED_HOSTS` | Hosts permitidos | `localhost,127.0.0.1` |
| `DB_NAME` | Nombre de la base de datos | `django_auth_db` |
| `DB_USER` | Usuario MySQL | `root` |
| `DB_PASSWORD` | Contraseña MySQL | `password` |
| `DB_HOST` | Host MySQL | `localhost` |
| `DB_PORT` | Puerto MySQL | `3306` |
| `EMAIL_HOST_USER` | Email SMTP | `tu@gmail.com` |
| `EMAIL_HOST_PASSWORD` | App password Gmail | `xxxx xxxx xxxx xxxx` |
| `TWILIO_ACCOUNT_SID` | SID de cuenta Twilio | `ACxxxxxx` |
| `TWILIO_AUTH_TOKEN` | Token de Twilio | `xxxxxxxx` |
| `TWILIO_PHONE_NUMBER` | Número Twilio | `+1234567890` |
| `GOOGLE_CLIENT_ID` | Client ID de Google OAuth | `xxx.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | Secret de Google OAuth | `GOCSPX-xxx` |
| `FACEBOOK_APP_ID` | App ID de Facebook | `123456789` |
| `FACEBOOK_APP_SECRET` | App Secret de Facebook | `xxxxxxxx` |
| `FRONTEND_URL` | URL del frontend | `http://localhost:3000` |
| `JWT_ACCESS_TOKEN_LIFETIME_MINUTES` | Expiración access token | `60` |
| `JWT_REFRESH_TOKEN_LIFETIME_DAYS` | Expiración refresh token | `7` |

### Obtener credenciales externas

**Gmail (App Password):**
1. Activa verificación en 2 pasos en tu cuenta Google
2. Ve a `Seguridad > Contraseñas de aplicación`
3. Genera una contraseña para "Correo / Otro"

**Twilio:**
1. Crea cuenta en [twilio.com](https://twilio.com)
2. Obtén `Account SID` y `Auth Token` del dashboard
3. Consigue un número de teléfono gratuito

**Google OAuth:**
1. Ve a [Google Cloud Console](https://console.cloud.google.com)
2. Crea un proyecto > APIs & Services > Credentials
3. Crea OAuth 2.0 Client ID (tipo: Web application)
4. Agrega `http://localhost:8000` a los orígenes autorizados

**Facebook Login:**
1. Ve a [developers.facebook.com](https://developers.facebook.com)
2. Crea una app > Agrega "Facebook Login"
3. Obtén `App ID` y `App Secret`

---

## 📡 Endpoints de la API

Base URL: `/api/v1/`

### 🔐 Autenticación (`/auth/`)

| Método | Endpoint | Descripción | Auth |
|---|---|---|---|
| POST | `/auth/register/` | Registro de usuario | ❌ |
| POST | `/auth/login/` | Login con email/password → JWT | ❌ |
| POST | `/auth/logout/` | Cerrar sesión (blacklist refresh) | ✅ |
| POST | `/auth/token/refresh/` | Renovar access token | ❌ |
| POST | `/auth/social/` | Login social (Google/Facebook) | ❌ |
| POST | `/auth/verify/send/` | Enviar código SMS | ✅ |
| POST | `/auth/verify/confirm/` | Verificar código SMS | ✅ |
| POST | `/auth/password/reset/` | Solicitar reset por email | ❌ |
| POST | `/auth/password/reset/confirm/` | Confirmar nuevo password | ❌ |
| POST | `/auth/password/change/` | Cambiar password (autenticado) | ✅ |

### 👥 Usuarios (`/users/`)

| Método | Endpoint | Descripción | Rol mínimo |
|---|---|---|---|
| GET | `/users/` | Listar usuarios + búsqueda | Personal |
| GET | `/users/me/` | Ver propio perfil | Usuario |
| PATCH | `/users/me/` | Actualizar propio perfil | Usuario |
| GET | `/users/{id}/` | Ver detalle de usuario | Personal |
| PATCH | `/users/{id}/` | Actualizar usuario | Admin |
| DELETE | `/users/{id}/` | Eliminar (desactivar) usuario | Admin |
| POST | `/users/{id}/assign-role/` | Asignar rol | Admin |

### Parámetros de búsqueda en `/users/`

```
?search=juan          → busca en nombre, apellido y email
?role=Admin           → filtra por rol
?is_verified=true     → filtra por verificación
?is_active=false      → filtra por estado
?page=2&page_size=10  → paginación
```

---

## 📋 Ejemplos de requests

### Registro

```bash
curl -X POST http://localhost:8000/api/v1/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "juan@example.com",
    "first_name": "Juan",
    "last_name": "Pérez",
    "birth_date": "1995-06-15",
    "phone_number": "+573001234567",
    "password": "MiPass123!",
    "password_confirm": "MiPass123!"
  }'
```

### Login

```bash
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "juan@example.com", "password": "MiPass123!"}'
```

### Login social

```bash
curl -X POST http://localhost:8000/api/v1/auth/social/ \
  -H "Content-Type: application/json" \
  -d '{"provider": "google", "access_token": "<token-del-frontend>"}'
```

### Verificar teléfono

```bash
# 1. Enviar código
curl -X POST http://localhost:8000/api/v1/auth/verify/send/ \
  -H "Authorization: Bearer <access_token>"

# 2. Confirmar código
curl -X POST http://localhost:8000/api/v1/auth/verify/confirm/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

### Formato de respuesta estándar

**Éxito:**
```json
{
  "success": true,
  "status_code": 200,
  "message": "Operación exitosa.",
  "data": { ... }
}
```

**Error:**
```json
{
  "success": false,
  "status_code": 400,
  "message": "Error al procesar la solicitud.",
  "errors": { "email": ["Este campo es requerido."] }
}
```

---

## 🧪 Tests

### Ejecutar todos los tests

```bash
pytest
```

### Con cobertura

```bash
pytest --cov=apps --cov-report=html
# Abre htmlcov/index.html en el navegador
```

### Tests específicos

```bash
# Solo tests de registro
pytest tests/accounts/test_register.py -v

# Solo tests de login
pytest tests/accounts/test_login.py -v

# Solo tests de usuarios
pytest tests/users/test_users.py -v

# Tests de un módulo con keyword
pytest -k "test_admin_can"
```

### Tests con unittest

```bash
python manage.py test tests --verbosity=2
```

---

## 👥 Sistema de roles

| Rol | Descripción | Permisos |
|---|---|---|
| **Admin** | Administrador total | CRUD completo, asignar roles, eliminar usuarios |
| **Personal** | Empleado/Staff | Ver y editar usuarios, no puede eliminar ni asignar roles |
| **Usuario** | Usuario regular | Solo su propio perfil |

Los roles se implementan mediante **Django Groups**. Al registrarse, el usuario recibe automáticamente el grupo `Usuario`.

### Cambiar el rol de un usuario

```bash
curl -X POST http://localhost:8000/api/v1/users/{id}/assign-role/ \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "Personal"}'
```

---

## 🚀 Despliegue en Render

### 1. Preparar el repositorio

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/tu-usuario/django-auth-api.git
git push -u origin main
```

### 2. Crear servicio en Render

1. Ve a [render.com](https://render.com) y crea una cuenta
2. Click en **New → Web Service**
3. Conecta tu repositorio de GitHub
4. Configura el servicio:

| Campo | Valor |
|---|---|
| **Name** | `django-auth-api` |
| **Runtime** | `Python 3` |
| **Build Command** | `./build.sh` |
| **Start Command** | `gunicorn config.wsgi:application --bind 0.0.0.0:$PORT` |

### 3. Variables de entorno en Render

En **Environment → Environment Variables**, agrega:

```
DJANGO_SETTINGS_MODULE = config.settings.production
SECRET_KEY             = <genera uno seguro>
DEBUG                  = False
ALLOWED_HOSTS          = tu-app.onrender.com
DB_NAME                = <de tu base de datos>
DB_USER                = <usuario>
DB_PASSWORD            = <password>
DB_HOST                = <host de MySQL en Render o PlanetScale>
DB_PORT                = 3306
DJANGO_SUPERUSER_EMAIL    = admin@tudominio.com
DJANGO_SUPERUSER_PASSWORD = <contraseña segura>
```

> **Base de datos:** Render no ofrece MySQL gratuito. Opciones gratuitas:
> - [PlanetScale](https://planetscale.com) — MySQL serverless, plan free
> - [Railway](https://railway.app) — MySQL con $5 crédito gratis

### 4. Generar SECRET_KEY segura

```python
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

### 5. Configurar WhiteNoise (ya incluido)

Los archivos estáticos son servidos automáticamente por WhiteNoise. El `build.sh` ejecuta `collectstatic` en cada deploy.

---

## 📤 Subir a GitHub paso a paso

```bash
# 1. Inicializar git (si no lo has hecho)
git init

# 2. Agregar todos los archivos
git add .

# 3. Primer commit
git commit -m "feat: initial project setup with auth API"

# 4. Crear repositorio en GitHub (sin README para evitar conflictos)
# Ve a github.com → New repository → NO inicialices con README

# 5. Conectar y subir
git remote add origin https://github.com/TU_USUARIO/TU_REPO.git
git branch -M main
git push -u origin main
```

### Commits siguientes

```bash
git add .
git commit -m "feat: add user CRUD endpoints"
git push
```

---

## 🔧 Comandos útiles

```bash
# Crear migraciones
python manage.py makemigrations

# Aplicar migraciones
python manage.py migrate

# Crear grupos de roles (ejecutar tras cada migrate)
python manage.py seed_roles

# Crear superusuario interactivo
python manage.py createsuperuser

# Crear superusuario desde env vars (para CI/CD)
python manage.py create_admin

# Limpiar tokens JWT expirados de la blacklist
python manage.py flushexpiredtokens

# Shell de Django
python manage.py shell_plus  # si tienes django-extensions

# Verificar configuración
python manage.py check --deploy
```

---

## 🏗️ Notas de arquitectura

- **Modelo de usuario personalizado** (`AbstractUser` sin campo `username`, login por email)
- **JWT con blacklist** para logout real (los tokens invalidados no pueden reusarse)
- **Verificación por SMS** con Twilio — códigos de 6 dígitos, expiran en 10 minutos
- **Soft delete** — los usuarios "eliminados" se desactivan (`is_active=False`), no se borran de la BD
- **Respuestas estándar** en todos los endpoints (`success`, `status_code`, `message`, `data`/`errors`)
- **Roles como Django Groups** — integración nativa con el sistema de permisos de Django
- **Separación de settings** — `base.py`, `development.py`, `production.py`
- **WhiteNoise** para archivos estáticos en producción sin necesidad de CDN

---

## 📦 Dependencias principales

| Paquete | Versión | Uso |
|---|---|---|
| Django | 4.2.x | Framework web |
| djangorestframework | 3.15.x | API REST |
| djangorestframework-simplejwt | 5.3.x | Autenticación JWT |
| django-allauth | 0.63.x | Login social |
| dj-rest-auth | 6.0.x | Endpoints de auth REST |
| mysqlclient | 2.2.x | Driver MySQL |
| twilio | 9.2.x | Envío de SMS |
| python-decouple | 3.8 | Variables de entorno |
| whitenoise | 6.7.x | Archivos estáticos |
| pytest-django | 4.8.x | Tests |
| factory-boy | 3.3.x | Fixtures de tests |

---

## 🤝 Contribuir

1. Fork del repositorio
2. Crea una rama: `git checkout -b feature/nueva-funcionalidad`
3. Commit: `git commit -m 'feat: descripción'`
4. Push: `git push origin feature/nueva-funcionalidad`
5. Abre un Pull Request

---

## 📄 Licencia

MIT License — libre para uso personal y comercial.
