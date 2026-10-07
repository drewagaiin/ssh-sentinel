# 🛰️ ssh-sentinel

**Detector de ataques contra SSH para Blue Team: encuentra fuerza bruta, password spraying y accesos sospechosos en tus registros, y te dice cómo prevenirlos.**

Un solo script en Bash + awk, sin dependencias, que entiende los registros de OpenSSH en todos sus formatos (syslog clásico, ISO 8601, journal de systemd y `sshd-session`/`sshd-auth` de OpenSSH 9.8+). Funciona como informe, **vigilando en tiempo real** como servicio de systemd, y con alertas por Telegram.

[![CI](https://github.com/drewagaiin/ssh-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/drewagaiin/ssh-sentinel/actions/workflows/ci.yml)
![Licencia MIT](https://img.shields.io/badge/licencia-MIT-blue)
![Bash 4+](https://img.shields.io/badge/bash-4%2B-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1110%20%C2%B7%20T1078-red)

---

## Por qué

Cualquier servidor con SSH expuesto a internet recibe **miles de intentos de acceso al día**. La mayoría son bots, pero entre ese ruido puede esconderse lo importante: **el intento que sí funcionó**. `ssh-sentinel` separa el ruido de lo urgente y prioriza por gravedad.

## Qué detecta

| Alerta | Severidad | Qué significa | MITRE ATT&CK |
|--------|-----------|---------------|--------------|
| `SSH-COMPROMISE` | 🟣 Crítica | **Acceso exitoso justo después de muchos fallos de esa IP** (24 h): probable contraseña adivinada | T1078, T1110 |
| `SSH-SUSPECT-LOGIN` | 🔴 Alta | Acceso con contraseña a una cuenta atacada desde **otras** IPs (botnet), o desde una IP que atacaba otras cuentas | T1078, T1110 |
| `SSH-BRUTE` | 🔴 Alta | Muchos intentos fallidos desde una IP en poco tiempo | T1110.001 |
| `SSH-SPRAY` | 🔴 Alta | Una IP prueba muchos usuarios distintos, aunque sea despacio para no levantar sospechas | T1110.003 |
| `SSH-ROOT` | 🔴/🟠 | Inicio de sesión directo como root (alta con contraseña, media con llave) | T1078.003 |
| `SSH-DISTRIBUTED` | 🟠 Media | Muchas IPs distintas contra el mismo usuario, pocas veces cada una (esquivan los umbrales por IP) | T1110 |
| `SSH-PASSWORD` | 🔵 Baja | Accesos con contraseña en lugar de llave SSH | T1110 |

Detalles y umbrales en [docs/DETECCIONES.md](docs/DETECCIONES.md).

## Uso rápido

```bash
git clone https://github.com/drewagaiin/ssh-sentinel.git
cd ssh-sentinel
chmod +x ssh-sentinel.sh

sudo ./ssh-sentinel.sh                       # analiza los últimos 7 días
sudo ./ssh-sentinel.sh --follow              # vigila en tiempo real
./ssh-sentinel.sh -f tests/fixtures/ataques-syslog.log   # prueba con un ataque de ejemplo
```

## Instalar en un servidor (servicio 24 h)

```bash
sudo ./install.sh                                   # programa, servicios y configuración
sudo nano /etc/ssh-sentinel/ssh-sentinel.conf       # umbrales, IPs de confianza, Telegram
sudo systemctl enable --now ssh-sentinel            # vigilancia en tiempo real
sudo systemctl enable --now ssh-sentinel-report.timer   # informe diario a las 07:00
journalctl -u ssh-sentinel -f                       # ver las alertas
```

| Pieza | Qué hace |
|-------|----------|
| `ssh-sentinel.service` | Vigila el journal y avisa al instante. Se reinicia solo si se corta. |
| `ssh-sentinel-report.timer` | Cada día: informe de texto en el journal y JSON en `/var/lib/ssh-sentinel/informe.json` (para un SIEM). |
| `/etc/ssh-sentinel/ssh-sentinel.conf` | Opciones en formato `CLAVE=valor` ([ejemplo](config/ssh-sentinel.conf.example)). La línea de comandos tiene prioridad. |

El servicio se ejecuta **sin ninguna capacidad de root**, sin poder escribir en el sistema ni ver `/home`, con filtro de llamadas al sistema y límite de memoria: exposición **1.7** en `systemd-analyze security` (la mayoría de servicios están por encima de 9). Para desinstalar: `sudo ./install.sh --uninstall`.

```text
== Alertas ==
  [CRITICO]  SSH-COMPROMISE    Acceso exitoso de 'deploy' después de 7 intentos fallidos contra esa cuenta
                               IP 192.0.2.50 · 2026-10-05 05:05:00 · MITRE T1078, T1110
  [ALTO]     SSH-BRUTE         Fuerza bruta: 19 intentos fallidos en menos de 10 minutos
                               IP 203.0.113.10 · 2026-10-05 03:02:01 · MITRE T1110.001
  [ALTO]     SSH-SPRAY         Password spraying: 6 usuarios distintos probados
                               IP 198.51.100.7 · 2026-10-05 03:55:00 · MITRE T1110.003

== Prevención recomendada ==
  1. Bloquear las IPs atacantes (revísalas antes de aplicar):
     sudo ufw prepend deny from 192.0.2.50 comment ssh-sentinel
     sudo ufw prepend deny from 203.0.113.10 comment ssh-sentinel
     sudo ufw prepend deny from 198.51.100.7 comment ssh-sentinel
  2. Bloqueo automático: sudo apt install fail2ban && sudo systemctl enable --now fail2ban
  3. Usar llaves SSH y desactivar contraseñas (ssh-copy-id, luego PasswordAuthentication no)
  4. Impedir el acceso directo de root: PermitRootLogin no
  5. URGENTE: hubo un acceso tras muchos fallos. Cambia la contraseña de esa cuenta, ...
```

## Prevención: sugiere, no actúa

`ssh-sentinel` **nunca bloquea nada por sí solo**. Un bloqueo automático equivocado puede dejarte fuera de tu propio servidor. En su lugar:

- Muestra los comandos de bloqueo y, con `--block-script bloqueos.sh`, genera un script para **revisarlo y ejecutarlo tú**. Funciona con **UFW** (Debian, Ubuntu, Kali) y **firewalld** (RHEL, Rocky, Alma).
- **Nunca sugiere bloquear** el propio equipo (`127.0.0.1`) ni la IP desde la que estás conectado.
- Marca las IPs de **red interna**: si un equipo de tu red ataca, bloquearlo no basta, hay que revisarlo porque probablemente está comprometido.
- Usa `ufw prepend`: UFW aplica la primera regla que coincide, así que un `deny` agregado al final después de un `allow 22` **nunca se aplicaría**. `prepend` lo pone el primero, funciona aunque no haya reglas (`insert 1` falla en ese caso; comprobado en ufw 0.36.2) y coloca cada regla en su lista, IPv4 o IPv6.
- Un ataque **distribuido** no se arregla bloqueando IPs: en ese caso recomienda desactivar las contraseñas o limitar SSH a tus redes.

Para un bloqueo automático y continuo, la herramienta adecuada es **fail2ban**: `ssh-sentinel` te dice si no lo tienes activo.

## Alertas por Telegram

1. Crea un bot hablando con **@BotFather** en Telegram y copia el token.
2. Envíale un mensaje a tu bot y obtén tu `chat_id` en `https://api.telegram.org/bot<TOKEN>/getUpdates`.
3. Guarda la configuración (solo root podrá leerla):

```bash
sudo mkdir -p /etc/ssh-sentinel
sudo nano /etc/ssh-sentinel/telegram.conf
```
```ini
TOKEN=123456789:AAH...
CHAT_ID=987654321
```
```bash
sudo chmod 600 /etc/ssh-sentinel/telegram.conf
sudo ./ssh-sentinel.sh --follow --telegram --dry-run   # prueba sin enviar
sudo ./ssh-sentinel.sh --follow --telegram             # en serio
```

Para el servicio, pon `TELEGRAM=yes` en `/etc/ssh-sentinel/ssh-sentinel.conf` y reinícialo. Solo se envían las alertas de severidad `FAIL_ON` o mayor (alta por defecto), como mucho 10 por minuto para que una botnet no inunde tu móvil. **Las críticas se envían siempre.**

## Opciones

| Opción | Descripción |
|--------|-------------|
| `-f, --file ARCHIVO` | Analiza un archivo (repetible, acepta `.gz`). Sin `-f` usa el journal o `/var/log/auth.log` |
| `--since TIEMPO` | Desde cuándo leer el journal (por defecto `"7 days ago"`) |
| `--threshold N` / `--window MIN` | Fuerza bruta: N fallos dentro de MIN minutos (10 / 10) |
| `--spray N` | Password spraying: N usuarios distintos (5) |
| `--after-fail N` | Fallos (últimas 24 h) que hacen sospechoso un acceso exitoso (5) |
| `--distributed N` | Ataque distribuido: N IPs distintas contra un usuario (20) |
| `--ignore LISTA` | IPs de confianza: `10.8.0.0/24,203.0.113.5,192.168.1.` (CIDR, IP exacta o prefijo terminado en `.` o `:`) |
| `--format json` / `-o ARCHIVO` | Informe JSON / guardar en archivo (permisos 600) |
| `--block-script ARCHIVO` | Genera un script de bloqueo para revisar (no se ejecuta) |
| `--firewall ufw\|firewalld` | Firewall de los comandos sugeridos (por defecto, el instalado) |
| `--follow` | Vigilancia en tiempo real (con `-f`, reproduce un archivo como si fuera en vivo) |
| `--telegram` / `--dry-run` / `--telegram-rate N` | Alertas por Telegram / simularlas / máximo por minuto (10) |
| `--fail-on SEV` | Severidad mínima para Telegram y para el código de salida 1 (por defecto `high`) |
| `--config ARCHIVO` / `--no-config` | Otro archivo de configuración / ninguno |

Códigos de salida: **0** sin alertas graves, **1** hay alertas de `--fail-on` o más, **2** error (opción no válida, registro ilegible...).

## Automatizar

Lo recomendado es el servicio y el timer de `install.sh`. Si prefieres cron:

```bash
# Cada día a las 07:00: informe JSON y Telegram si hay algo grave
0 7 * * *  /usr/local/bin/ssh-sentinel --since "24 hours ago" --format json -o /var/lib/ssh-sentinel/informe.json
```

## Cómo cuenta (y por qué es exacto)

OpenSSH registra un usuario inexistente en **dos líneas** (`Invalid user admin` y `Failed password for invalid user admin`). Contarlas por separado duplicaría los ataques. `ssh-sentinel` las une por sesión (IP + puerto). También expande las líneas `message repeated N times` que comprime rsyslog, e ignora los fallos de llave pública, que son normales cuando un cliente prueba varias llaves.

Para decidir si un acceso exitoso es sospechoso solo cuentan los fallos de las **últimas 24 horas**: equivocarse una vez al día no es un ataque.

Estas reglas están verificadas con **ataques reales** contra un OpenSSH 9.6 registrado por rsyslog ([real-rsyslog.log](tests/fixtures/real-rsyslog.log), [real-inyeccion.log](tests/fixtures/real-inyeccion.log)).

## Seguridad del propio script

| Riesgo | Mitigación |
|--------|------------|
| Un registro manipulado inyecta comandos en el script de bloqueo | Solo se aceptan IPs válidas (IPv4 con 4 números ≤ 255 o IPv6); cubierto por pruebas |
| **El atacante pone una IP falsa en su nombre de usuario** (`x from 8.8.8.8 port 22`) para que bloquees a un inocente | La IP se toma de la cola fija que escribe sshd, no del primer `from`. Probado contra OpenSSH 9.6 real |
| Un usuario local falsifica ataques con `logger -t sshd` | En el journal solo se aceptan mensajes de sshd escritos por root (`_UID=0`) |
| Una línea falsa con `message repeated 999999999 times` cuelga el análisis | Tope de 100 repeticiones por línea |
| Un registro dañado da un falso "sin alertas" | Si algo no se puede leer, termina con error (código 2) |
| La configuración se usa para ocultar ataques (`IGNORE`) | Debe pertenecer a root y no ser modificable por otros; se lee como texto y se valida |
| El token de Telegram queda expuesto | Se lee como texto (nunca con `source`), se exige permiso `600` y se pasa a `curl` por la entrada estándar, no como argumento visible en `ps` |
| Secuestro de binarios al usar `sudo` | `PATH` fijo y `LC_ALL=C` |
| Ataque de enlace simbólico al guardar informes | Se rechazan rutas que sean enlaces y la escritura es atómica |
| Bloquearte a ti mismo | Nunca sugiere bloquear `127.0.0.1` ni tu IP de conexión |

## Rendimiento

- 300.000 intentos de 60.000 IPs distintas (un día de ataque distribuido) se analizan en unos **12 segundos**.
- 200.000 intentos de una sola IP seguidos de 200 accesos: **2 segundos**.
- En vivo, con 2 millones de intentos al día, usa menos de **400 MB** (tiene topes de memoria para funcionar meses).

## Pruebas

```bash
bats tests/sentinel.bats
```
53 pruebas: conteo exacto en cada formato, cada detección, prevención segura, engaños con registros manipulados, configuración, instalador, Telegram, modo en vivo, rendimiento y casos límite. El CI las ejecuta en **Kali, Debian 12, Ubuntu 22.04 y 24.04**, pasa ShellCheck y verifica los servicios de systemd.

## Proyectos relacionados

- [linux-audit](https://github.com/drewagaiin/linux-audit): auditoría de configuración de seguridad alineada con CIS. `linux-audit` revisa **cómo está configurado** SSH; `ssh-sentinel` revisa **quién lo está atacando**.

## Uso responsable

Analiza solo registros de equipos propios o con autorización. Los informes contienen IPs y nombres de usuario: trátalos como confidenciales.

## Licencia

[MIT](LICENSE)
