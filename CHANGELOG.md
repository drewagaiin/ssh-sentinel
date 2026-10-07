# Cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [versionado semántico](https://semver.org/lang/es/).

## [1.1.0] - 2026-10-06

Revisión de seguridad para uso en empresa. Cada corrección tiene su prueba (53 en total).

### Seguridad (corregido)
- **IP falsa en el nombre de usuario**: un atacante podía usar el usuario `x from 8.8.8.8 port 22` para que se sugiriera bloquear una IP inocente. Comprobado contra un OpenSSH 9.6 real. Ahora la IP se toma de la cola fija que escribe sshd.
- **Mensajes falsificados de otros programas**: `sshd[…]` solo se acepta en su posición (no en medio de la línea), y en el journal solo se aceptan mensajes escritos por root (`_UID=0`), que un usuario local no puede falsificar con `logger`.
- **IPs no válidas** (`999.1.1.1`, `::`, nombres de host) se descartan antes de llegar al firewall.
- **Bytes de control y no ASCII** en nombres de usuario se sustituyen: no rompen la terminal ni el JSON.
- **`message repeated` con números enormes** se limita a 100: una línea falsificada ya no puede colgar el análisis.

### Corregido
- **Modo en vivo con mawk** (Debian, Ubuntu, Kali): las alertas podían tardar horas en aparecer porque mawk lee por bloques. Ahora se usa `-W interactive`.
- **Cambio de año**: en enero, las líneas de diciembre se fechaban en el futuro.
- **Archivo dañado** (`.gz` corrupto): antes daba "Sin alertas"; ahora es un error (código 2).
- **`--since` se ignoraba** con `/var/log/auth.log`; ahora se aplica a cualquier origen y se valida.
- **El modo en vivo solo leía el journal o `/var/log/auth.log`**: ahora también `/var/log/secure` (RHEL) y elige el origen que tiene registros de SSH.
- **Bloqueos con UFW**: se usa `ufw prepend`, que pone el bloqueo antes de cualquier `allow`, funciona sin reglas previas (comprobado en ufw 0.36.2) y coloca cada regla en su lista IPv4 o IPv6. Antes se elegía entre `insert 1` y `deny` según el estado del firewall.
- **Acceso tras fallos**: solo cuentan los fallos de las últimas 24 horas. Equivocarse una vez al día ya no genera una alerta crítica.
- **Con miles de alertas**, el informe de texto muestra 5 por tipo y resume el resto.

### Añadido
- `SSH-DISTRIBUTED`: muchas IPs contra un mismo usuario (botnets que esquivan los umbrales por IP). Opción `--distributed`.
- `SSH-SUSPECT-LOGIN`: acceso con contraseña a una cuenta atacada desde otras IPs, o desde una IP con fallos recientes contra otras cuentas.
- `--ignore` con redes CIDR (`10.0.0.0/8`) e IPs exactas.
- Soporte de **firewalld** (`--firewall`), `--block-script` (alias del antiguo `--ufw-script`).
- **Archivo de configuración** `/etc/ssh-sentinel/ssh-sentinel.conf`, leído como texto y con comprobación de permisos.
- **Servicio systemd** endurecido (exposición 1.7 en `systemd-analyze security`), **informe diario** con timer e **instalador** (`install.sh`).
- Telegram: límite de mensajes por minuto (`--telegram-rate`); las alertas críticas se envían siempre. Solo se envía lo que llega a `--fail-on`.
- Memoria acotada en modo en vivo: olvida IPs inactivas tras 24 h y limita la cola de fallos.

## [1.0.0] - 2026-10-06

### Añadido
- Detección de fuerza bruta (ventana deslizante), password spraying, acceso tras fallos, login de root y accesos con contraseña, mapeados a MITRE ATT&CK.
- Formatos de registro: syslog clásico, ISO 8601 (rsyslog moderno), journal de systemd, `sshd-session` (OpenSSH 9.8+), archivos `.gz` y líneas `message repeated N times`.
- Modo en vivo (`--follow`) y repetición de archivos para practicar.
- Alertas por Telegram con token protegido y modo simulado (`--dry-run`).
- Prevención: comandos y script de bloqueo para revisar (`--ufw-script`), recomendaciones de fail2ban, llaves y `PermitRootLogin`.
- Informe JSON y códigos de salida para automatizar.
- 28 pruebas y CI en Kali, Debian 12, Ubuntu 22.04 y 24.04.

### Decisiones tomadas durante el desarrollo (encontradas con pruebas reales)
- Un usuario inexistente genera dos líneas en OpenSSH: se cuentan como un solo intento.
- No se sugiere bloquear `127.0.0.1` ni la IP de tu propia conexión.
- `ufw insert 1` cuando hay reglas (si no, un `allow 22` previo anularía el bloqueo) y `ufw deny` cuando no hay ninguna (porque `insert 1` falla en ese caso). Sustituido por `ufw prepend` en 1.1.0.
- Las rutas de salida se validan al inicio: dentro de una tubería, un error de seguridad solo cerraba un subproceso.
- Fechas y escapado JSON hechos en awk: el informe de 17.000 IPs pasó de 3 minutos a 1 segundo; 300.000 intentos se analizan en unos 10 segundos.
