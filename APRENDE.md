# Aprende con este proyecto

Guía para usar `ssh-sentinel` en tu Kali, entender cómo funciona y practicar como un analista de Blue Team.

## 1. Probarlo sin riesgo (con registros de ejemplo)

```bash
cd ~/ssh-sentinel
chmod +x ssh-sentinel.sh
./ssh-sentinel.sh -f tests/fixtures/ataques-syslog.log
```

Verás 4 alertas: una intrusión, fuerza bruta, password spraying y accesos con contraseña. Abre `tests/fixtures/ataques-syslog.log` con `less` y busca cada ataque en el registro original. **Leer registros crudos es la habilidad más básica de un analista SOC.**

Ahora mira lo mismo "en vivo", como si estuviera pasando:
```bash
./ssh-sentinel.sh --follow -f tests/fixtures/ataques-syslog.log
```

## 2. Atacarte a ti mismo (laboratorio en tu Kali)

> Toma un snapshot antes. Todo ocurre dentro de tu VM, contra tu propio equipo.

**Terminal 1**, enciende SSH y deja el vigilante en vivo:
```bash
sudo systemctl start ssh
sudo ./ssh-sentinel.sh --follow --threshold 5
```

**Terminal 2**, haz de atacante: intenta entrar con contraseñas incorrectas varias veces (escribe cualquier cosa cuando te pida la contraseña):
```bash
ssh root@localhost
ssh admin@localhost
ssh oracle@localhost
ssh test@localhost
ssh pi@localhost
```

En la terminal 1 verás aparecer las alertas **en el momento**. Después prueba el informe completo:
```bash
sudo ./ssh-sentinel.sh --since "10 minutes ago"
```

Fíjate en que **no sugiere bloquear 127.0.0.1**: bloquear tu propio equipo rompería cosas.

**El engaño de la IP falsa.** Intenta entrar con un nombre de usuario que contenga una IP:
```bash
ssh "x from 8.8.8.8 port 22"@localhost
sudo grep '8.8.8.8' /var/log/auth.log; sudo journalctl -t sshd -t sshd-session | grep 8.8.8.8
```
OpenSSH guarda el nombre tal cual. Una herramienta ingenua creería que el atacante es 8.8.8.8 (el DNS de Google) y te diría que lo bloquees. `ssh-sentinel` toma la IP del final de la línea, que escribe sshd y el atacante no controla.

Al terminar, apaga SSH si no lo usas:
```bash
sudo systemctl stop ssh
```

## 3. Instalarlo como servicio (como en una empresa)

```bash
sudo ./install.sh
sudo systemctl enable --now ssh-sentinel
journalctl -u ssh-sentinel -f          # aquí aparecen las alertas
```
Repite los ataques de la sección 2 y míralos aparecer en el journal. Comprueba lo protegido que está el servicio:
```bash
systemd-analyze security ssh-sentinel  # cuanto más bajo, mejor (0 a 10)
```
Para quitarlo: `sudo systemctl disable --now ssh-sentinel && sudo ./install.sh --uninstall`.

## 4. Cómo está construido (3 etapas)

```
registros  →  PARSER (awk)  →  ANALIZADOR (awk)  →  INFORME (bash)
 (texto)      evento normal      cuenta y decide      texto / JSON / bloqueos
```

| Etapa | Qué hace | Dónde está |
|-------|----------|------------|
| Parser | Convierte cada línea, en cualquier formato, en `epoch TIPO ip usuario puerto método` | `PARSER_AWK` |
| Analizador | Cuenta intentos por IP, ventana deslizante, usuarios distintos, accesos tras fallos | `ANALYZER_AWK` |
| Accesos | ¿Un acceso exitoso es sospechoso? Mira solo las últimas 24 h, con contadores que no se recalculan | `LOGIN_AWK` |
| En vivo | La misma lógica, pero avisa en el instante | `STREAM_AWK` |
| Informe | Ordena, muestra, sugiere prevención, genera JSON y el script de bloqueo | funciones `render_*` |

**Idea clave:** separar "entender el formato" de "decidir si es un ataque". Así, soportar un formato nuevo solo cambia el parser.

Puedes ver la salida de la primera etapa (se ejecuta en un `bash -c` aparte para que el script no cambie la configuración de tu terminal):
```bash
bash -c 'source ./ssh-sentinel.sh; parse < tests/fixtures/ataques-syslog.log | head'
```

## 5. Conceptos de seguridad que practicas

- **Fuerza bruta vs. password spraying**: muchas contraseñas contra un usuario, o pocas contraseñas contra muchos usuarios (y despacio, para no levantar alarmas).
- **Ventana deslizante**: 10 fallos en un día es normal; 10 fallos en 2 minutos, no.
- **El evento más importante es el éxito**, no el fallo: miles de fallos son ruido de internet; un acceso después de esos fallos es un incidente.
- **Prevención segura**: nunca automatizar un bloqueo que pueda dejarte fuera; sugerir y que una persona decida.
- **Entrada no confiable**: un atacante controla parte del texto de los registros (por ejemplo, el nombre de usuario). Nada de ese texto debe ejecutarse ni decidir qué IP se bloquea. Mira `tests/fixtures/malicioso.log` y `real-inyeccion.log`.
- **Ataques distribuidos**: una botnet reparte los intentos entre miles de IPs para no superar ningún umbral por IP. Se detecta mirando la cuenta atacada, no la IP.
- **Mínimo privilegio**: el servicio corre como root pero sin ninguna capacidad especial. Si alguien lo engañara, no podría hacer daño.
- **Fallar de forma segura**: si un registro no se puede leer, es mejor un error que un "todo bien" falso.

## 6. Conceptos de Bash y awk

| Concepto | Ejemplo |
|----------|---------|
| Heredoc con comillas para guardar un programa awk | `read -r -d '' PARSER_AWK <<'AWK'` |
| Arreglos asociativos en awk | `fails[ip]++` |
| Fechas sin `mktime` (funciona en mawk de Debian/Kali) | `days_from_civil()` |
| Tuberías por etapas | `read_logs \| parse \| sort \| awk` |
| Por qué una variable "se pierde" dentro de una tubería | `pick_source` se llama fuera de la tubería |
| Rendimiento: evitar un subproceso por línea | fechas y JSON hechos en awk |
| mawk lee por bloques: en vivo hay que pedirle línea a línea | `-W interactive` |
| Leer configuración sin ejecutarla (nunca `source`) | `load_config` |

## 7. Preguntas de entrevista

- ¿Qué diferencia hay entre fuerza bruta y password spraying? ¿Por qué el spraying es más difícil de detectar?
- Tienes 50.000 intentos fallidos al día. ¿Qué miras primero? (Respuesta: los accesos exitosos.)
- ¿Por qué no bloquear automáticamente toda IP que falla 3 veces?
- ¿Por qué `ufw deny` puede no funcionar si ya existe `allow 22`?
- ¿Qué haces si el atacante es una IP de tu red interna?
- ¿Cómo evitas que un registro manipulado ejecute comandos en tu herramienta?
- Un atacante usa el usuario `x from 8.8.8.8 port 22`. ¿Qué IP bloquearía una herramienta mal hecha? ¿Por qué es peligroso?
- ¿Cómo detectas una botnet que hace 1 intento por IP desde 5.000 IPs?

## 8. Retos (cada uno es un buen commit)

1. **Fácil:** agrega la detección `SSH-NIGHT`, un acceso exitoso entre las 00:00 y las 05:00.
2. **Fácil:** muestra en el informe cuántos intentos fueron contra `root`.
3. **Medio:** detecta **acceso desde una IP nueva**: un usuario que entra desde una IP que nunca había usado.
4. **Medio:** opción `--html` reutilizando el estilo del informe de linux-audit.
5. **Difícil:** integra fail2ban: lee `fail2ban-client status sshd` y muestra qué IPs ya están bloqueadas.
6. **Difícil:** `--ignore` con redes CIDR de IPv6 (`2001:db8::/32`).

Antes de cada commit: `shellcheck ssh-sentinel.sh` y `bats tests/sentinel.bats`.
