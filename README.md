# 🛡️ Security Bot — Revisor de Seguridad DevSecOps

<div align="center">

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-844FBA?style=for-the-badge&logo=terraform&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)
![OpenCode](https://img.shields.io/badge/OpenCode-CLI-111111?style=for-the-badge)

**Revisión automática de seguridad para cambios de infraestructura en pull requests**

Auditoría de Terraform y manifiestos Kubernetes mediante proveedores compatibles con la API de OpenAI o la suscripción local de OpenCode.

</div>

---

## 📋 Descripción

**security-bot** es una herramienta DevSecOps que analiza los cambios de infraestructura de los pull requests y publica una revisión estructurada con evidencias, severidad y recomendaciones.

El bot revisa únicamente archivos Terraform (`.tf`) y manifiestos Kubernetes (`.yaml`/`.yml`). Su comportamiento es **advisory**: informa de los riesgos detectados, pero no bloquea ni aprueba la combinación del pull request.

### Modos de uso

| Modo | Ejecución | Autenticación de IA | Resultado |
|---|---|---|---|
| GitHub Actions | Automática en cada pull request relevante | Secretos del proveedor configurado | Revisión publicada en el pull request |
| OpenCode CLI | Manual y local | Suscripción personal de OpenCode | Revisión en terminal o publicada opcionalmente |

---

## 🏗️ Arquitectura

```
Pull request con cambios de infraestructura
└── GitHub Actions
    ├── Checkout del historial completo
    ├── Diff base...head (.tf, .yaml, .yml)
    ├── scripts/security_review.py
    │   ├── Decodificación y truncado seguro
    │   ├── Proveedor compatible con OpenAI
    │   ├── Validación del JSON de respuesta
    │   └── Publicación de la revisión en GitHub
    └── Review advisory con comentarios inline

Ejecución local
└── scripts/local_review.py
    ├── Git range, archivo de diff o stdin
    ├── OpenCode CLI y suscripción personal
    ├── Mismo prompt, esquema y parser que el modo cloud
    └── Salida en terminal o publicación opcional mediante gh
```

---

## 🛠️ Stack tecnológico

| Componente | Tecnología |
|---|---|
| Lenguaje | Python 3, únicamente librería estándar |
| Automatización | GitHub Actions |
| Infraestructura analizada | Terraform y Kubernetes YAML |
| Proveedores cloud | OpenAI, Groq, Together AI, OpenRouter y otros compatibles |
| Ejecución local | OpenCode CLI |
| Publicación local | GitHub CLI (`gh`) |
| Pruebas | `unittest` |

---

## 📂 Estructura del repositorio

```
security-bot/
├── .github/
│   └── workflows/
│       └── security-review.yml       # Workflow de revisión automática
├── scripts/
│   ├── security_review.py            # Entrada cloud y lógica compartida
│   └── local_review.py               # Entrada local mediante OpenCode CLI
├── tests/
│   ├── test_security_review.py       # Pruebas del flujo cloud y parser
│   ├── test_local_review.py           # Pruebas del flujo local
│   ├── fake_provider.py               # Proveedor falso para smoke tests
│   └── fixtures/infra.diff            # Diff de ejemplo con vulnerabilidades
├── example/
│   ├── main.tf                        # Ejemplo Terraform
│   └── deployment.yaml                # Ejemplo Kubernetes
├── .gitignore
└── README.md
```

---

## 🚀 Configuración rápida en GitHub Actions

### Prerrequisitos

- Un repositorio GitHub con GitHub Actions habilitado.
- Permiso `pull-requests: write` para el workflow.
- Un proveedor compatible con `chat/completions`.

### 1. Configurar secretos

En **Settings → Secrets and variables → Actions**, añade estos secretos:

| Secreto | Descripción | Ejemplo |
|---|---|---|
| `AI_API_KEY` | Clave del proveedor de IA | `gsk_...` |
| `AI_BASE_URL` | URL raíz compatible con OpenAI | `https://api.groq.com/openai/v1` |
| `AI_MODEL` | Identificador del modelo | `llama-3.3-70b-versatile` |

El script añade automáticamente `/chat/completions` a `AI_BASE_URL`.

### 2. Proveedores compatibles

| Proveedor | `AI_BASE_URL` | Modelo de ejemplo |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |
| Together AI | `https://api.together.xyz/v1` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` |
| OpenRouter | `https://openrouter.ai/api/v1` | `openai/gpt-4o-mini` |
| Ollama | `http://localhost:11434/v1` | `llama3.1` |

> **Nota:** GitHub-hosted runners no pueden acceder al `localhost` de tu equipo. Usa Ollama únicamente para ejecuciones manuales o locales.

### 3. Activar el workflow

El workflow se ejecuta en pull requests `opened`, `synchronize` y `reopened` cuando se modifican archivos `.tf`, `.yaml` o `.yml`.

```bash
git checkout -b test/security-review
git add example/main.tf
git commit -m "test: add infrastructure change"
git push -u origin test/security-review
```

Después, abre un pull request contra `main`. La revisión aparecerá como **AI infrastructure security review**.

---

## 💻 Uso local con OpenCode CLI

El modo local ejecuta el mismo análisis sin necesitar `AI_API_KEY`, `AI_BASE_URL` ni `AI_MODEL`. Requiere tener `opencode` instalado y autenticado.

### Instalación y ejemplos

Desde la raíz del repositorio:

```bash
# Revisar un rango Git
python3 scripts/local_review.py main...mi-rama

# Revisar un archivo de diff
python3 scripts/local_review.py --diff-file tests/fixtures/infra.diff

# Revisar un diff recibido por stdin
git diff main...mi-rama -- '*.tf' '*.yaml' '*.yml' | \
  python3 scripts/local_review.py

# Elegir otro modelo de OpenCode
python3 scripts/local_review.py main...mi-rama \
  --model opencode-go/deepseek-v4-flash

# Publicar la revisión en un pull request
python3 scripts/local_review.py main...mi-rama --post-pr 12
```

### Entradas admitidas

Las entradas son mutuamente excluyentes:

| Entrada | Opción | Comportamiento |
|---|---|---|
| Rango Git | `BASE...HEAD` | Ejecuta `git diff` para archivos de infraestructura |
| Archivo | `--diff-file PATH` | Lee un diff unificado desde disco |
| Entrada estándar | Sin rango ni archivo, o `--diff-file -` | Lee el diff desde stdin |

El resultado se muestra como texto legible con riesgo general, severidad, archivo, línea, evidencia y recomendación. El JSON se utiliza internamente para validar la respuesta.

### Requisitos locales

- `opencode` disponible en `PATH` y autenticado.
- Ejecutar el modo de rango dentro de un repositorio Git.
- `gh` autenticado si se utiliza `--post-pr`.

---

## 🔍 Riesgos detectados

El auditor busca evidencias concretas de problemas como:

- Servicios, puertos o redes expuestos a `0.0.0.0/0` o `::/0`.
- Secretos, contraseñas o tokens en texto plano.
- Permisos IAM demasiado amplios o acciones `*`.
- Falta de cifrado en reposo o en tránsito.
- Buckets y contenedores públicos.
- Contenedores Kubernetes privilegiados o ejecutándose como root.
- Uso de `hostPath`, `hostNetwork`, `hostPID` o montajes peligrosos.
- Imágenes con etiqueta `latest` o sin digest.
- Falta de límites de recursos y RBAC excesivamente permisivo.

Solo se reportan hallazgos respaldados por el diff analizado; las recomendaciones generales sin evidencia no generan findings.

---

## 🧪 Pruebas

### Pruebas unitarias

No es necesario instalar dependencias externas:

```bash
python -m unittest discover -s tests -v
```

Las pruebas cubren el procesamiento de diffs, extracción y validación de JSON, normalización de severidades, selección de comentarios inline y renderizado de revisiones.

### Smoke test local con proveedor falso

```bash
# Terminal 1
python3 tests/fake_provider.py 8123

# Terminal 2 (Linux/macOS)
DIFF_B64="$(base64 -w0 tests/fixtures/infra.diff)" \
  AI_API_KEY=fake \
  AI_BASE_URL=http://127.0.0.1:8123/v1 \
  AI_MODEL=fake-model \
  python3 scripts/security_review.py
```

La ejecución debe mostrar dos hallazgos de ejemplo y el modo `dry-run`.

---

## ⚙️ Variables opcionales

| Variable | Valor predeterminado | Finalidad |
|---|---:|---|
| `AI_MAX_DIFF_CHARS` | `40000` | Máximo de caracteres enviados al modelo |
| `AI_TIMEOUT` | `90` | Tiempo límite de la petición, en segundos |
| `POST_CLEAN_REVIEW` | `true` | Publicar una revisión cuando no hay hallazgos |

Los diffs grandes se limitan conservando los cambios más recientes. Si el proveedor devuelve un error de contexto, el script reduce el tamaño y reintenta de forma controlada.

---

## ⚠️ Limitaciones y solución de problemas

| Síntoma | Solución |
|---|---|
| El workflow no se ejecuta | Comprueba que el PR modifica `.tf`, `.yaml` o `.yml`. |
| Falta una variable `AI_*` | Configura los tres secretos requeridos en el repositorio. |
| Error HTTP `401` o `403` | Revisa `AI_API_KEY` y `AI_BASE_URL`. |
| Error HTTP `404` | Comprueba la URL `/v1` y el nombre del modelo. |
| Error de contexto | Reduce `AI_MAX_DIFF_CHARS` o usa un modelo con mayor contexto. |
| No se publica la revisión | Verifica que `GITHUB_TOKEN` tenga `pull-requests: write` o que `gh` esté autenticado. |
| PR procedente de un fork | Se omite por seguridad: los forks no exponen los secretos del repositorio. |

> El workflow ejecuta código del commit revisado. Úsalo únicamente con ramas de confianza y no lo modifiques para ejecutar código de terceros procedente de forks.

---

## 📄 Licencia

Este proyecto no incluye actualmente un archivo de licencia explícito. Añade uno antes de distribuirlo públicamente.
