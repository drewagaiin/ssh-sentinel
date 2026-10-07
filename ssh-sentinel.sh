#!/usr/bin/env bash
# =============================================================================
#  ssh-sentinel — Detector de ataques contra SSH (Blue Team)
#
#  Analiza los registros de SSH y detecta:
#    · Fuerza bruta (muchos intentos fallidos en poco tiempo)   MITRE T1110.001
#    · Password spraying (muchos usuarios distintos)            MITRE T1110.003
#    · Acceso exitoso DESPUÉS de muchos fallos (posible intrusión) MITRE T1078
#    · Inicios de sesión de root y con contraseña                MITRE T1078.003
#  y propone medidas de prevención (bloqueos de firewall, fail2ban, llaves).
#
#  GARANTÍA DE DISEÑO: por defecto es de solo lectura. Nunca bloquea nada por
#  sí solo: genera los comandos para que una persona los revise y aplique.
#  Solo usa la red si se pide explícitamente una alerta por Telegram.
#
#  Licencia: MIT
# =============================================================================

set -uo pipefail

# --- Endurecimiento del propio script (igual que linux-audit) ----------------
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL=C
umask 077
shopt -u patsub_replacement 2>/dev/null || true

readonly VERSION="1.1.0"

# --- Opciones -----------------------------------------------------------------
# Orden de prioridad: valores por defecto < archivo de configuración < línea de comandos
FILES=()             # archivos de registro a analizar (vacío = automático)
SINCE="7 days ago"   # desde cuándo analizar (journal y /var/log/auth.log)
SINCE_SET=0          # 1 si se pidió --since a propósito
FORMAT="text"        # text | json
OUTPUT_FILE=""
USE_COLOR=1
FOLLOW=0
THRESHOLD=10         # intentos fallidos de una IP dentro de la ventana → fuerza bruta
WINDOW_MIN=10        # ventana de tiempo en minutos
SPRAY=5              # usuarios distintos desde una IP → password spraying
AFTER_FAIL=5         # fallos previos para considerar sospechoso un acceso exitoso
DIST=20              # IPs distintas contra un mismo usuario → ataque distribuido
TOP=10
IGNORE=""            # IPs a ignorar: CIDR, IP exacta o prefijo, separados por comas
FAIL_ON="high"
BLOCK_SCRIPT=""
FIREWALL=""          # ufw | firewalld (vacío = detectar)
TELEGRAM=0
TG_CONFIG="/etc/ssh-sentinel/telegram.conf"
TG_RATE=10           # máximo de mensajes de Telegram por minuto en modo en vivo
DRY_RUN=0
CONFIG_FILE="/etc/ssh-sentinel/ssh-sentinel.conf"
TTL=86400            # modo en vivo: segundos que se recuerda una IP inactiva

C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_MAG=""; C_GRY=""; C_BLD=""; C_RST=""

usage() {
    cat <<EOF
ssh-sentinel v${VERSION} — Detector de ataques contra SSH

Uso: sudo $0 [opciones]

Origen de los registros (por defecto: journal de systemd o /var/log/auth.log):
  -f, --file ARCHIVO     Analiza este archivo completo (se puede repetir; acepta .gz)
      --since TIEMPO     Desde cuándo analizar (def: "7 days ago")

Detección:
      --threshold N      Fallos de una IP dentro de la ventana = fuerza bruta (def: 10)
      --window MIN       Ventana de tiempo en minutos (def: 10)
      --spray N          Usuarios distintos desde una IP = password spraying (def: 5)
      --after-fail N     Fallos previos que hacen sospechoso un acceso exitoso (def: 5)
      --distributed N    IPs distintas contra un usuario = ataque distribuido (def: 20)
      --ignore LISTA     IPs de confianza a ignorar, separadas por comas:
                         CIDR (10.0.0.0/8), IP exacta (10.0.0.5) o prefijo (192.168.1.)
      --top N            Cuántas IPs y usuarios mostrar (def: 10)

Salida y prevención:
      --format FORMATO   text (def) o json
  -o, --output ARCHIVO   Guarda el informe en ARCHIVO (permisos 600)
      --block-script ARCH  Genera un script con los bloqueos sugeridos para revisarlo
                         (NO se ejecuta solo). Alias: --ufw-script
      --firewall FW      ufw o firewalld (def: el que esté instalado)
      --fail-on SEV      Código de salida 1 si hay alertas de esta severidad o
                         mayor: low|medium|high|critical (def: high)
      --no-color         Sin colores

Modo en vivo y alertas:
      --follow           Vigila SSH en tiempo real y avisa al instante
                         (con -f, reproduce el archivo como si fuera en vivo)
      --telegram         Envía las alertas por Telegram
                         (config: /etc/ssh-sentinel/telegram.conf)
      --no-telegram      No envía a Telegram aunque lo pida la configuración
      --telegram-config  Otro archivo de configuración de Telegram
      --telegram-rate N  Máximo de mensajes por minuto en vivo (def: 10)
      --dry-run          Muestra las alertas de Telegram sin enviarlas

Configuración:
      --config ARCHIVO   Archivo de opciones (def: /etc/ssh-sentinel/ssh-sentinel.conf
                         si existe). La línea de comandos tiene prioridad.
      --no-config        No lee ningún archivo de configuración
  -h, --help             Esta ayuda
  -v, --version          Versión

Códigos de salida: 0 sin alertas graves · 1 hay alertas >= --fail-on · 2 error

Ejemplos:
  sudo $0
  sudo $0 --since "24 hours ago" --block-script bloqueos.sh
  $0 -f /var/log/auth.log.1 --format json
  sudo $0 --follow --telegram
EOF
}

die() { printf 'Error: %s\n' "$1" >&2; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }

sev_num() {
    case "$1" in critical) echo 4 ;; high) echo 3 ;; medium) echo 2 ;; low) echo 1 ;; *) echo 0 ;; esac
}
sev_label() {
    case "$1" in critical) echo "CRÍTICO" ;; high) echo "ALTO" ;; medium) echo "MEDIO" ;; low) echo "BAJO" ;; *) echo "INFO" ;; esac
}

setup_colors() {
    [[ -t 1 ]] || USE_COLOR=0
    if [[ $USE_COLOR -eq 1 ]]; then
        C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'
        C_MAG=$'\e[35m'; C_GRY=$'\e[90m'; C_BLD=$'\e[1m'; C_RST=$'\e[0m'
    fi
}

sev_color() {
    case "$1" in critical) printf '%s' "$C_MAG" ;; high) printf '%s' "$C_RED" ;;
                 medium) printf '%s' "$C_YEL" ;; *) printf '%s' "$C_BLU" ;; esac
}

# Fecha legible a partir del "epoch" calculado desde el registro. Las horas se
# tratan como UTC en todo el programa para mostrar la hora tal cual aparece en
# el registro (sin conversiones de zona horaria).
fmt_time() { [[ -n "${1:-}" && "$1" != 0 ]] && date -u -d "@$1" '+%Y-%m-%d %H:%M:%S' 2>/dev/null; }

json_esc() {
    local s=$1
    s=${s//\\/\\\\}; s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}; s=${s//$'\r'/\\r}
    printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

# Una IP solo puede contener dígitos, letras hex, puntos y dos puntos. Se valida
# antes de ponerla en un comando de firewall: un registro manipulado no debe
# poder inyectar comandos en el script de bloqueo.
valid_ip() {
    local o
    if [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
        return 0
    fi
    [[ "$1" =~ ^[0-9A-Fa-f:.]+$ && "$1" == *:* && "$1" =~ [1-9A-Fa-f] && ${#1} -le 45 ]]
}

# Nunca se sugiere bloquear el propio equipo: rompería servicios locales.
is_loopback() { [[ "$1" == 127.* || "$1" == ::1 || "$1" == ::ffff:127.* ]]; }

# Red interna (RFC 1918 / IPv6 local): el atacante es un equipo de tu propia
# red, que probablemente está comprometido. Bloquearlo no basta: hay que revisarlo.
is_private() {
    [[ "$1" == 10.* || "$1" == 192.168.* || "$1" == 169.254.* || "$1" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. \
       || "${1,,}" == fc* || "${1,,}" == fd* || "${1,,}" == fe80:* ]]
}

# IP desde la que TÚ estás conectado (si entraste por SSH): no se bloquea
MY_IP=""
detect_my_ip() {
    MY_IP=${SSH_CLIENT:-}; MY_IP=${MY_IP%% *}
    if [[ -z "$MY_IP" ]] && have who; then
        MY_IP=$(who -m 2>/dev/null | sed -n 's/.*(\([0-9A-Fa-f:.]*\)).*/\1/p' | head -n1)
    fi
}

# =============================================================================
#  ETAPA 1 — PARSER
#  Convierte cada línea de registro de SSH en un evento normalizado:
#    epoch  TIPO  ip  usuario  puerto  método
#  TIPO: FAIL (contraseña incorrecta), INVALID (usuario inexistente), OK (acceso)
#  Entiende el formato clásico de syslog, el ISO 8601 (journal y rsyslog
#  modernos), los procesos sshd y sshd-session (OpenSSH 9.8+) y las líneas
#  "message repeated N times" que comprime rsyslog.
# =============================================================================
read -r -d '' PARSER_AWK <<'AWK' || true  # read -d '' devuelve 1 al llegar al final: es normal
function days_from_civil(y, m, d,    era, yoe, doy, doe) {
    y -= (m <= 2)
    era = int((y >= 0 ? y : y - 399) / 400)
    yoe = y - era * 400
    doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
    doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
    return era * 146097 + doe - 719468
}
function to_epoch(y, mo, d, hms,    t) {
    split(hms, t, ":")
    return days_from_civil(y + 0, mo + 0, d + 0) * 86400 + t[1] * 3600 + t[2] * 60 + int(t[3])
}
# Año de un "epoch" (inverso de days_from_civil)
function civil_year(e,    z, era, doe, yoe, doy, mp, m) {
    z = int(e / 86400) + 719468
    era = int((z >= 0 ? z : z - 146096) / 146097)
    doe = z - era * 146097
    yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
    doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
    mp = int((5 * doy + 2) / 153)
    m = mp + (mp < 10 ? 3 : -9)
    return sprintf("%04d", yoe + era * 400 + (m <= 2))
}
# Número de una IPv4 (o -1 si no lo es). Sin operaciones de bits: compatible con mawk.
function ip4num(s,    o, n, i) {
    if (s !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return -1
    n = split(s, o, ".")
    for (i = 1; i <= 4; i++) if (o[i] + 0 > 255) return -1
    return ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]
}
# Una IP solo puede tener dígitos, letras hex, puntos y dos puntos. "::" o
# "::0" (dirección vacía) no valen: en un firewall podrían significar "todas".
function valid(s) {
    if (s ~ /^[0-9.]+$/) return ip4num(s) >= 0
    return (s ~ /^[0-9A-Fa-f:.]+$/ && s ~ /:/ && s ~ /[1-9A-Fa-f]/ && length(s) <= 45)
}
# --ignore: CIDR IPv4 (10.0.0.0/8), IP exacta (10.0.0.5, 2001:db8::5)
#          o prefijo terminado en "." o ":" (192.168.1. / 2001:db8:)
function ignored(ip,    i, n) {
    for (i = 1; i <= nign; i++) {
        if (igt[i] == "c") {
            if ((n = ip4num(ip)) >= 0 && int(n / igs[i]) == igb[i]) return 1
        } else if (igt[i] == "e") {
            if (ip == ign[i]) return 1
        } else if (ign[i] != "" && index(ip, ign[i]) == 1) return 1
    }
    return 0
}
function emit(type, ip, user, port, method,    i) {
    sub(/^::[fF][fF][fF][fF]:/, "", ip)        # IPv4 vista como IPv6 (::ffff:1.2.3.4)
    if (!valid(ip) || port !~ /^[0-9]*$/ || ignored(ip)) return
    if (since > 0 && ts < since) return
    gsub(/[\001-\037\177-\377]/, "?", user)     # sin controles ni bytes raros (terminal, TSV, JSON)
    if (length(user) > 64) user = substr(user, 1, 64) "..."
    if (user == "") user = "(sin-nombre)"
    if (method !~ /^[A-Za-z0-9\/@.-]+$/) method = "?"
    for (i = 0; i < rep; i++)
        printf "%d\t%s\t%s\t%s\t%s\t%s\n", ts, type, ip, user, port, method
    if (live) fflush()                          # en vivo: cada evento sale al instante
}
# El nombre de usuario lo elige el ATACANTE y puede contener espacios y hasta
# "from 8.8.8.8 port 22". Lo que sshd escribe al final de la línea es fiable:
# "... from IP port N [ssh2]". Por eso se busca el "from" desde el FINAL y se
# exige que sea exactamente esa cola. (Así se evita el engaño clásico que hacía
# bloquear una IP inocente.) Devuelve la posición de ese "from" o 0.
function tail_from(extra,    i) {
    i = nw - 3 - extra
    if (i >= 1 && w[i] == "from" && w[i + 2] == "port") return i
    return 0
}
function join(a, b,    s, i) {
    s = ""
    for (i = a; i <= b; i++) s = s (i > a ? " " : "") w[i]
    return s
}
BEGIN {
    nign = split(ignore, ign, ",")
    for (i = 1; i <= nign; i++) {
        if (split(ign[i], c, "/") == 2) {
            igt[i] = "c"; igs[i] = 2 ^ (32 - c[2]); igb[i] = int(ip4num(c[1]) / igs[i])
        } else if (ip4num(ign[i]) >= 0 || (ign[i] ~ /:/ && ign[i] !~ /:$/)) igt[i] = "e"
        else igt[i] = "p"
    }
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " ")
    for (i = 1; i <= 12; i++) mon[mn[i]] = i
    # "Ahora" y "desde" llegan como hora local "AAAA MM DD HH:MM:SS"
    split(now, nn, " "); now_e = to_epoch(nn[1], nn[2], nn[3], nn[4]); year = nn[1] + 0
    # En vivo el programa funciona meses: "ahora" se actualiza con el reloj
    # (srand() devuelve la hora; funciona en mawk y gawk) para el cambio de año.
    if (live) { srand(); clock_off = now_e - srand() }
    since = 0
    if (since_s != "") { split(since_s, ss, " "); since = to_epoch(ss[1], ss[2], ss[3], ss[4]) }
}
{
    # --- Marca de tiempo ---
    if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
        ts = to_epoch(substr($1, 1, 4), substr($1, 6, 2), substr($1, 9, 2), substr($1, 12, 8))
    } else if ($1 in mon) {
        # syslog clásico no trae el año: se usa el actual, salvo que la fecha
        # quede en el futuro (ej.: el 2 de enero leyendo líneas del 31 de diciembre)
        if (live) { srand(); now_e = srand() + clock_off; year = substr(civil_year(now_e), 1, 4) + 0 }
        ts = to_epoch(year, mon[$1], $2, $3)
        if (ts > now_e + 86400) ts = to_epoch(year - 1, mon[$1], $2, $3)
    } else if ($1 ~ /^[0-9]+(\.[0-9]+)?$/ && $1 > 100000000) {
        ts = int($1)                                    # journalctl -o short-unix
    } else {
        next
    }
    # --- Mensaje de sshd ---
    # El programa debe estar EN SU SITIO (campo 5 en syslog clásico, 3 en ISO),
    # no en cualquier parte: "otraapp[7]: texto sshd[1]: Failed..." no es sshd.
    p = ($1 in mon) ? 5 : 3
    if ($p !~ /^sshd(-session|-auth)?\[[0-9]+\]:$/) next
    msg = $0
    for (i = 1; i <= p; i++) sub(/^[ \t]*[^ \t]+/, "", msg)
    sub(/^[ \t]+/, "", msg)
    rep = 1
    if (msg ~ /^message repeated [0-9]+ times: \[ /) {
        # Una sesión de sshd repite como mucho unas decenas de líneas iguales;
        # el tope evita que una línea falsificada dispare el tiempo de análisis
        split(msg, r, " "); rep = r[3] + 0
        if (rep > 100) rep = 100
        sub(/^message repeated [0-9]+ times: \[ /, "", msg)
        sub(/\][ \t]*$/, "", msg)
    }
    nw = split(msg, w, " ")
    if (msg ~ /^Failed (password|keyboard-interactive\/pam) for /) {
        if (!(f = tail_from(1))) next                    # ... from IP port N ssh2
        s = (w[4] == "invalid" && w[5] == "user" && f >= 6) ? 6 : 4
        emit("FAIL", w[f + 1], join(s, f - 1), w[f + 3], w[2])
    } else if (msg ~ /^Invalid user /) {
        if (f = tail_from(0))                            # ... from IP port N
            emit("INVALID", w[f + 1], join(3, f - 1), w[f + 3], "-")
        else if (nw >= 4 && w[nw - 1] == "from")         # OpenSSH antiguo: sin puerto
            emit("INVALID", w[nw], join(3, nw - 2), "", "-")
    } else if (msg ~ /^Accepted [^ ]+ for [^ ]+ from [^ ]+ port [0-9]+ /) {
        # Un acceso solo es posible con una cuenta real (sin espacios):
        # la posición de cada campo es fija.
        emit("OK", w[6], w[4], w[8], w[2])
    }
}
AWK

# =============================================================================
#  Lógica común de los dos analizadores: ¿un acceso exitoso es sospechoso?
#  Se miran solo los fallos de las ÚLTIMAS 24 HORAS: un error al escribir la
#  contraseña cada día de la semana no es un ataque.
# =============================================================================
read -r -d '' LOGIN_AWK <<'AWK' || true  # read -d '' devuelve 1 al llegar al final: es normal
# Una sola cola, en orden de llegada, con cada fallo de las últimas 24 h
# (hora, IP, usuario) y contadores que se actualizan al entrar y al salir de
# la ventana. Así cada acceso se evalúa en tiempo constante, aunque una IP
# lleve cientos de miles de intentos.
#   wip[ip]      fallos de la IP          wipu[ip]   usuarios distintos de la IP
#   wu[u]        fallos contra el usuario wuip[u]    IPs distintas contra el usuario
#   wpair[ip,u]  fallos de esa IP contra ese usuario
function day_push(ip, u, t,    k) {
    day_prune(t)
    # En vivo hay un tope de memoria: con una avalancha (más de qmax fallos en
    # 24 h) se olvidan antes los más antiguos en lugar de agotar la RAM.
    if (qmax > 0 && gq_tail - gq_head + 1 >= qmax) day_drop()
    k = ip SUBSEP u
    gq_t[++gq_tail] = t; gq_k[gq_tail] = k
    if (!(k in wpair)) { wpair[k] = 0; wipu[ip]++; wuip[u]++ }
    wpair[k]++; wip[ip]++; wu[u]++
}
function day_drop(    k, e, ip, u) {
    k = gq_k[gq_head]; split(k, e, SUBSEP); ip = e[1]; u = e[2]
    if (--wip[ip] <= 0) { delete wip[ip]; delete wipu[ip] }
    if (--wu[u] <= 0) { delete wu[u]; delete wuip[u] }
    if (--wpair[k] <= 0) {
        delete wpair[k]
        if (ip in wipu) wipu[ip]--
        if (u in wuip) wuip[u]--
    }
    delete gq_t[gq_head]; delete gq_k[gq_head]; gq_head++
}
function day_prune(t) {
    if (gq_head == 0) gq_head = 1
    while (gq_head <= gq_tail && t - gq_t[gq_head] > 86400) day_drop()
}
# Al entrar 'u' desde 'ip' (últimas 24 h):
#   rf fallos de la IP · rp de la IP contra ese usuario · ru usuarios que probó la IP
#   of fallos contra ese usuario desde OTRAS IPs · oi cuántas IPs eran
function day_stats(ip, u, t,    k) {
    day_prune(t)
    k = ip SUBSEP u
    rf = (ip in wip) ? wip[ip] : 0
    ru = (ip in wipu) ? wipu[ip] : 0
    rp = (k in wpair) ? wpair[k] : 0
    of = ((u in wu) ? wu[u] : 0) - rp
    oi = ((u in wuip) ? wuip[u] : 0) - (rp > 0 ? 1 : 0)
}
# Veredicto de un acceso exitoso (después de day_stats): "severidad<TAB>id<TAB>texto" o ""
function login_verdict(u, me) {
    if (rp >= afterf)
        return "critical\tSSH-COMPROMISE\t" sprintf("Acceso exitoso de '%s' después de %d intentos fallidos contra esa cuenta", u, rp)
    if (rf >= afterf && ru >= spray)
        return "critical\tSSH-COMPROMISE\t" sprintf("Acceso exitoso de '%s' desde una IP que probó %d usuarios (%d intentos)", u, ru, rf)
    if (rf >= afterf)
        return "high\tSSH-SUSPECT-LOGIN\t" sprintf("Acceso de '%s' desde una IP con %d intentos fallidos recientes", u, rf)
    # Ataque distribuido: una IP adivina la contraseña y entra OTRA que no falló
    if ((me == "password" || me == "keyboard-interactive/pam") && of >= afterf && oi >= 1)
        return "high\tSSH-SUSPECT-LOGIN\t" sprintf("Acceso con contraseña de '%s', una cuenta atacada: %d intentos desde %d IP(s)", u, of, oi)
    return ""
}
AWK

# =============================================================================
#  ETAPA 2 — ANALIZADOR (modo informe)
#  Recorre los eventos en orden cronológico y calcula, por IP:
#    · intentos fallidos (sin contar doble los usuarios inexistentes)
#    · máximo de intentos dentro de la ventana de tiempo (ventana deslizante)
#    · usuarios distintos probados
#    · accesos exitosos y si llegaron después de muchos fallos
#  Salida en registros TSV: S (resumen) I (IP) U (usuario) L (acceso) A (alerta)
# =============================================================================
read -r -d '' ANALYZER_AWK <<'AWK' || true  # read -d '' devuelve 1 al llegar al final: es normal
function attempt(t, ip, u,    k, n) {
    fails[ip]++; total_fail++
    if (!(ip in first)) { first[ip] = t; nips++ }
    last[ip] = t
    ucount[u]++; ulast[u] = t
    k = ip SUBSEP u
    if (!(k in seen)) {
        seen[k] = 0; nusers[ip]++; uips[u]++
        if (nusers[ip] <= 8) ulist[ip] = ulist[ip] (nusers[ip] > 1 ? "," : "") u
    }
    seen[k]++
    day_push(ip, u, t)
    # Ventana deslizante: cola de tiempos por IP
    n = ++qt[ip]; tq[ip, n] = t
    if (!(ip in qh)) qh[ip] = 1
    while (t - tq[ip, qh[ip]] > win) { delete tq[ip, qh[ip]]; qh[ip]++ }
    if (n - qh[ip] + 1 > maxw[ip]) { maxw[ip] = n - qh[ip] + 1; maxw_t[ip] = t }
    if (t < tmin || tmin == 0) tmin = t
    if (t > tmax) tmax = t
}
{
    t = $1; ty = $2; ip = $3; u = $4; port = $5; me = $6
    sk = ip SUBSEP port
    if (ty == "INVALID") {
        # "Invalid user X" y luego "Failed password for invalid user X" son
        # el MISMO intento: se cuenta una vez y se guarda un crédito.
        attempt(t, ip, u); credit[sk]++
    } else if (ty == "FAIL") {
        if (sk in credit) { if (--credit[sk] <= 0) delete credit[sk] }
        else attempt(t, ip, u)
    } else if (ty == "OK") {
        total_ok++
        if (t < tmin || tmin == 0) tmin = t
        if (t > tmax) tmax = t
        okip[ip]++
        day_stats(ip, u, t)
        printf "L\t%d\t%s\t%s\t%s\t%d\n", t, u, ip, me, rf
        v = login_verdict(u, me)
        if (v != "") {
            split(v, vv, "\t")
            printf "A\t%s\t%s\t%s\t%s\t%d\tT1078, T1110\n", vv[1], vv[2], vv[3], ip, t
        }
        if (u == "root") {
            printf "A\t%s\tSSH-ROOT\tInicio de sesión directo como root (%s)\t%s\t%d\tT1078.003\n", (me == "password" ? "high" : "medium"), me, ip, t
        }
        if (me == "password" || me == "keyboard-interactive/pam") {
            pw++
            if (!(u in pwuser)) { pwuser[u] = 1; pwusers = pwusers (pwusers == "" ? "" : ",") u }
        }
    }
}
END {
    for (ip in fails) {
        if (maxw[ip] >= thr) {
            printf "A\thigh\tSSH-BRUTE\tFuerza bruta: %d intentos fallidos en menos de %d minutos\t%s\t%d\tT1110.001\n", maxw[ip], win / 60, ip, maxw_t[ip]
        }
        if (nusers[ip] >= spray) {
            printf "A\thigh\tSSH-SPRAY\tPassword spraying: %d usuarios distintos probados\t%s\t%d\tT1110.003\n", nusers[ip], ip, last[ip]
        }
        printf "I\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", ip, fails[ip], nusers[ip], first[ip], last[ip], maxw[ip], ((ip in okip) ? okip[ip] : 0), ulist[ip]
    }
    for (u in ucount) {
        printf "U\t%s\t%d\t%d\n", u, ucount[u], uips[u]
        # Muchas IPs, pocas veces cada una: esquiva los umbrales por IP (botnets)
        if (uips[u] >= dist && u != "(sin-nombre)")
            printf "A\tmedium\tSSH-DISTRIBUTED\tAtaque distribuido contra '%s': %d intentos desde %d IPs distintas\t-\t%d\tT1110\n", u, ucount[u], uips[u], ulast[u]
    }
    if (pw > 0) {
        printf "A\tlow\tSSH-PASSWORD\t%d acceso(s) con contraseña en lugar de llave\t-\t0\tT1110\n", pw
        printf "S\tpwusers\t%s\n", pwusers
    }
    printf "S\tfails\t%d\nS\toks\t%d\nS\tips\t%d\nS\ttmin\t%d\nS\ttmax\t%d\n", total_fail, total_ok, nips, tmin, tmax
}
AWK

# =============================================================================
#  ETAPA 2b — ANALIZADOR EN VIVO (modo --follow)
#  Misma lógica, pero emite cada alerta en el momento en que ocurre.
#  Salida: hora  severidad  id  ip  descripción
# =============================================================================
read -r -d '' STREAM_AWK <<'AWK' || true  # read -d '' devuelve 1 al llegar al final: es normal
function alert(sev, id, ip, text) { printf "%d\t%s\t%s\t%s\t%s\n", t, sev, id, ip, text; fflush() }
function attempt(ip, u,    k, n) {
    fails[ip]++; lastseen[ip] = t
    ufails[u]++; ulast[u] = t
    k = ip SUBSEP u
    if (!(k in seen)) {
        seen[k] = 0; nusers[ip]++; uips[u]++
        if (nusers[ip] == spray) alert("high", "SSH-SPRAY", ip, sprintf("Password spraying: %d usuarios distintos probados", nusers[ip]))
        if (uips[u] == dist && u != "(sin-nombre)" && !(u in udone)) {
            udone[u] = 1
            alert("medium", "SSH-DISTRIBUTED", "-", sprintf("Ataque distribuido contra '%s': %d intentos desde %d IPs distintas", u, ufails[u], uips[u]))
        }
    }
    seen[k]++
    day_push(ip, u, t)
    n = ++qt[ip]; tq[ip, n] = t
    if (!(ip in qh)) qh[ip] = 1
    while (t - tq[ip, qh[ip]] > win) { delete tq[ip, qh[ip]]; qh[ip]++ }
    # Avisa al cruzar el umbral y, si el ataque sigue, como mucho una vez por ventana
    if (n - qh[ip] + 1 >= thr && (!(ip in lastbf) || t - lastbf[ip] > win)) {
        lastbf[ip] = t
        alert("high", "SSH-BRUTE", ip, sprintf("Fuerza bruta: %d intentos fallidos en menos de %d minutos", n - qh[ip] + 1, win / 60))
    }
}
# Funcionando semanas como servicio, la memoria no puede crecer sin límite:
# cada hora se olvidan las IPs y usuarios sin actividad en las últimas 24 h.
function gc(    ip, k, p, dead, j, u) {
    for (ip in lastseen) if (t - lastseen[ip] > ttl) dead[ip] = 1
    for (ip in dead) {
        for (j = qh[ip]; j <= qt[ip]; j++) delete tq[ip, j]
        delete fails[ip]; delete nusers[ip]; delete qh[ip]; delete qt[ip]
        delete lastbf[ip]; delete lastseen[ip]
    }
    for (k in seen) {
        split(k, p, SUBSEP)
        if (p[1] in dead) {
            if (p[2] in ulast) { ufails[p[2]] -= seen[k]; uips[p[2]]-- }
            delete seen[k]
        }
    }
    for (u in ulast) if (t - ulast[u] > ttl) { delete ulast[u]; delete ufails[u]; delete uips[u]; delete udone[u] }
    for (k in credit) if (t - creditt[k] > 3600) { delete credit[k]; delete creditt[k] }
    lastgc = t
}
{
    t = $1; ty = $2; ip = $3; u = $4; sk = ip SUBSEP $5
    if (t - lastgc > 3600) gc()
    if (ty == "INVALID") { attempt(ip, u); credit[sk]++; creditt[sk] = t }
    else if (ty == "FAIL") {
        if (sk in credit) { if (--credit[sk] <= 0) { delete credit[sk]; delete creditt[sk] } }
        else attempt(ip, u)
    }
    else if (ty == "OK") {
        day_stats(ip, u, t)
        v = login_verdict(u, $6)
        if (v != "") { split(v, vv, "\t"); alert(vv[1], vv[2], ip, vv[3]) }
        if (u == "root")
            alert(($6 == "password" ? "high" : "medium"), "SSH-ROOT", ip, sprintf("Inicio de sesión directo como root (%s)", $6))
    }
}
AWK

# =============================================================================
#  Lectura de los registros
# =============================================================================
SOURCE_DESC=""
SOURCE_KIND=""      # files | journal | file:RUTA | none

# Filtro del journal: solo mensajes de sshd (sshd-session en OpenSSH 9.8+ y
# sshd-auth en 10.x) Y escritos por root (_UID=0). El campo _UID lo pone el
# propio journal y no se puede falsificar: así un usuario local no puede
# inventar ataques con 'logger -t sshd' para que bloquees una IP inocente.
JOURNAL_MATCH=(_UID=0 SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session SYSLOG_IDENTIFIER=sshd-auth)

# Se decide en el shell principal (no dentro de una tubería, donde las
# variables se perderían al terminar el subproceso).
pick_source() {
    local f
    if [[ ${#FILES[@]} -gt 0 ]]; then
        SOURCE_KIND=files; SOURCE_DESC="archivos: ${FILES[*]}"; return
    fi
    if have journalctl && [[ -n "$(journalctl -q -n1 "${JOURNAL_MATCH[@]}" 2>/dev/null)" ]]; then
        SOURCE_KIND=journal; SOURCE_DESC="journal de systemd (desde: $SINCE)"; return
    fi
    for f in /var/log/auth.log /var/log/secure; do
        if [[ -r "$f" ]]; then
            SOURCE_KIND="file:$f"; SOURCE_DESC="$f y su rotación .1 (desde: $SINCE)"; return
        fi
    done
    SOURCE_KIND=none; SOURCE_DESC="ninguno"
}

# "Desde cuándo" como hora local. Se aplica a cualquier origen (no solo al
# journal): antes, con /var/log/auth.log, --since se ignoraba en silencio.
# Con -f se analiza el archivo entero, salvo que se pida --since a propósito.
SINCE_S=""
resolve_since() {
    SINCE_S=""
    [[ "$SOURCE_KIND" == files && $SINCE_SET -eq 0 ]] && return 0
    if [[ "$SOURCE_KIND" == journal ]]; then
        journalctl -q -n0 --since "$SINCE" >/dev/null 2>&1 || die "--since no válido: '$SINCE' (ej.: \"24 hours ago\", \"2026-10-01\")"
    fi
    SINCE_S=$(date -d "$SINCE" '+%Y %m %d %H:%M:%S' 2>/dev/null)
    [[ -n "$SINCE_S" || "$SOURCE_KIND" == journal ]] || die "--since no válido: '$SINCE' (ej.: \"24 hours ago\", \"2026-10-01\")"
    return 0
}

# Devuelve error si un archivo no se pudo leer (por ejemplo, un .gz dañado).
# Un análisis incompleto que dice "sin alertas" es peor que un error.
read_logs() {
    local f rc=0
    if [[ "$SOURCE_KIND" == files ]]; then
        for f in "${FILES[@]}"; do
            case "$f" in
                *.gz) zcat -- "$f" || rc=1 ;;
                *)    cat -- "$f" || rc=1 ;;
            esac
        done
        return $rc
    fi
    case "$SOURCE_KIND" in
        journal)
            journalctl -q --no-pager -o short-iso --since "$SINCE" "${JOURNAL_MATCH[@]}" 2>/dev/null
            return 0 ;;
        file:*)
            f=${SOURCE_KIND#file:}
            if [[ -r "$f.1" ]]; then cat -- "$f.1" || rc=1; fi
            cat -- "$f" || rc=1
            return $rc ;;
    esac
}

# mawk (el awk por defecto en Debian, Ubuntu y Kali) lee la entrada en bloques
# grandes: en vivo, una alerta podía tardar HORAS en aparecer en un servidor
# tranquilo. "-W interactive" hace que procese cada línea en cuanto llega.
awk_live_opts() {
    AWK_LIVE=()
    awk -W version 2>/dev/null | grep -q mawk && AWK_LIVE=(-W interactive)
    return 0
}
AWK_LIVE=()

NOW_S=""
parse() {
    local live=${1:-0} opts=()
    [[ $live -eq 1 ]] && opts=(${AWK_LIVE[@]+"${AWK_LIVE[@]}"})
    awk ${opts[@]+"${opts[@]}"} -v live="$live" -v now="${NOW_S:-$(date '+%Y %m %d %H:%M:%S')}" -v since_s="$SINCE_S" -v ignore="$IGNORE" "$PARSER_AWK"
}

# =============================================================================
#  Telegram (opcional, solo si se pide)
# =============================================================================
TG_TOKEN=""; TG_CHAT=""

load_telegram() {
    TG_TOKEN=${SSH_SENTINEL_TG_TOKEN:-}; TG_CHAT=${SSH_SENTINEL_TG_CHAT:-}
    if [[ -z "$TG_TOKEN" || -z "$TG_CHAT" ]]; then
        [[ -r "$TG_CONFIG" ]] || die "configura Telegram en $TG_CONFIG (ver README) o con las variables SSH_SENTINEL_TG_TOKEN y SSH_SENTINEL_TG_CHAT"
        # El archivo contiene un secreto: solo su dueño debe poder leerlo
        if [[ -n "$(find "$TG_CONFIG" -maxdepth 0 -perm /077 2>/dev/null)" ]]; then
            die "$TG_CONFIG es legible por otros usuarios (contiene tu token). Usa: chmod 600 $TG_CONFIG"
        fi
        # Se lee como texto, nunca con 'source': no debe poder ejecutar código
        TG_TOKEN=$(sed -n 's/^[[:space:]]*TOKEN[[:space:]]*=[[:space:]]*//p' "$TG_CONFIG" | head -n1 | tr -d '"'"'"' \r')
        TG_CHAT=$(sed -n 's/^[[:space:]]*CHAT_ID[[:space:]]*=[[:space:]]*//p' "$TG_CONFIG" | head -n1 | tr -d '"'"'"' \r')
    fi
    [[ "$TG_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || die "TOKEN de Telegram con formato inválido"
    [[ "$TG_CHAT" =~ ^-?[0-9]+$ ]] || die "CHAT_ID de Telegram con formato inválido"
    have curl || die "se necesita curl para enviar alertas: sudo apt install curl"
}

send_telegram() {
    local text=$1
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '%s[telegram simulado]%s %s\n' "$C_GRY" "$C_RST" "${text//$'\n'/ | }" >&2
        return 0
    fi
    # El token va por la entrada estándar (-K -), no como argumento: así no
    # aparece en 'ps' ni en el historial para otros usuarios del equipo.
    printf 'url = "https://api.telegram.org/bot%s/sendMessage"\ndata-urlencode = "chat_id=%s"\n' "$TG_TOKEN" "$TG_CHAT" \
      | curl -fsS --max-time 10 -K - --data-urlencode "text=$text" -o /dev/null \
      || printf 'Aviso: no se pudo enviar la alerta por Telegram\n' >&2
}

# =============================================================================
#  Modo en vivo
# =============================================================================
run_follow() {
    local src live=1 logf=""
    awk_live_opts
    pick_source
    case "$SOURCE_KIND" in
        files)   src="reproducción de: ${FILES[*]}"; live=0 ;;
        journal) src="journal de systemd en vivo" ;;
        file:*)  logf=${SOURCE_KIND#file:}; src="$logf en vivo" ;;
        *)  # Aún no hay registros de SSH (servidor nuevo): se espera en el journal
            have journalctl || die "no hay de dónde leer en vivo (ni journal ni /var/log/auth.log ni /var/log/secure)"
            SOURCE_KIND=journal; src="journal de systemd en vivo (todavía sin registros de SSH)" ;;
    esac
    if [[ $live -eq 1 && $EUID -ne 0 ]] && ! id -nG 2>/dev/null | grep -qwE 'adm|systemd-journal'; then
        printf 'Aviso: sin sudo no podrás ver los registros de SSH y parecerá que no hay ataques.\n' >&2
    fi
    [[ $SINCE_SET -eq 1 ]] && printf 'Aviso: --since no se usa en modo en vivo.\n' >&2
    printf '%sssh-sentinel v%s%s — vigilando SSH (%s). Ctrl+C para salir.\n' "$C_BLD" "$VERSION" "$C_RST" "$src"
    printf '%sUmbrales: %d fallos en %d min · %d usuarios · acceso tras %d fallos · %d IPs contra un usuario%s\n\n' \
        "$C_GRY" "$THRESHOLD" "$WINDOW_MIN" "$SPRAY" "$AFTER_FAIL" "$DIST" "$C_RST"

    {
        if [[ $live -eq 0 ]]; then read_logs
        elif [[ -n "$logf" ]]; then tail -n0 -F -- "$logf" 2>/dev/null
        else journalctl -f -n0 -q -o short-iso "${JOURNAL_MATCH[@]}"
        fi
    } | parse "$live" \
      | awk ${AWK_LIVE[@]+"${AWK_LIVE[@]}"} -F'\t' -v thr="$THRESHOLD" -v win=$((WINDOW_MIN * 60)) -v spray="$SPRAY" -v afterf="$AFTER_FAIL" \
            -v dist="$DIST" -v ttl="$TTL" -v qmax=400000 "$LOGIN_AWK"$'\n'"$STREAM_AWK" \
      | {
        # Límite de mensajes: durante un ataque de una botnet pueden salir cientos
        # de alertas por minuto. Telegram las rechazaría y el móvil sería inútil.
        # Las que sobran se cuentan y se avisa en el siguiente mensaje.
        local t sev id ip text iptxt win_start=$SECONDS sent=0 held=0 note min_sev
        min_sev=$(sev_num "$FAIL_ON")
        while IFS=$'\t' read -r t sev id ip text; do
            printf '%s %s%-8s%s %-17s %-16s %s\n' "$(fmt_time "$t")" "$(sev_color "$sev")" "$(sev_label "$sev" | sed 's/Í/I/')" "$C_RST" "$id" "$ip" "$text"
            # A Telegram solo va lo que llega a --fail-on (por defecto: alto o crítico)
            [[ $TELEGRAM -eq 1 && $(sev_num "$sev") -ge $min_sev ]] || continue
            if (( SECONDS - win_start >= 60 )); then win_start=$SECONDS; sent=0; fi
            # Una posible intrusión (crítica) se envía SIEMPRE, aunque se supere el límite
            if (( sent >= TG_RATE )) && [[ "$sev" != critical ]]; then held=$((held + 1)); continue; fi
            note=""
            (( held > 0 )) && note=$'\n'"(+$held alertas anteriores no enviadas para no saturar; revisa el registro del servicio)"
            held=0; sent=$((sent + 1))
            iptxt="IP: $ip"; [[ "$ip" == - ]] && iptxt="IP: varias (ataque distribuido)"
            send_telegram "🚨 ssh-sentinel en ${HOSTNAME:-?}
$(sev_label "$sev") · $id
$iptxt
${text:0:300}
Hora: $(fmt_time "$t")$note"
        done
        if (( held > 0 )); then
            send_telegram "ssh-sentinel en ${HOSTNAME:-?}: $held alertas no enviadas para no saturar; revisa el registro del servicio"
        fi
      }
    # Con un archivo, terminar es normal. En vivo, significa que la fuente se cortó:
    # se devuelve error (código 2) para que systemd reinicie el servicio.
    if [[ $live -eq 1 ]]; then
        printf 'Error: la fuente de registros en vivo terminó inesperadamente\n' >&2
        return 2
    fi
    return 0
}

# =============================================================================
#  Modo informe
# =============================================================================
declare -A SUM=()
ALERTS=(); IPS=(); USERS=(); LOGINS=()
WORST=0; WORST_SEV="none"

analyze() {
    local raw
    raw=$(read_logs | parse | sort -s -t$'\t' -k1,1n \
          | awk -F'\t' -v thr="$THRESHOLD" -v win=$((WINDOW_MIN * 60)) -v spray="$SPRAY" -v afterf="$AFTER_FAIL" \
                -v dist="$DIST" "$LOGIN_AWK"$'\n'"$ANALYZER_AWK") \
        || die "no se pudieron leer todos los registros (¿archivo dañado o sin permiso?). No se genera un informe incompleto."
    # Se reparte por tipo con awk + mapfile: un bucle 'while read' de bash sobre
    # 100.000 registros tardaba más de 10 segundos.
    local k v
    while IFS=$'\t' read -r k v; do SUM[$k]=$v; done < <(awk -F'\t' '$1 == "S" { print $2 "\t" $3 }' <<< "$raw")
    # Alertas ordenadas: severidad, tipo y, dentro de cada tipo, la más grande primero
    mapfile -t ALERTS < <(awk -F'\t' '$1 == "A" {
            r = ($2 == "critical") ? 0 : ($2 == "high") ? 1 : ($2 == "medium") ? 2 : 3
            n = match($4, /[0-9]+ (intentos|usuarios)/) ? substr($4, RSTART, RLENGTH) + 0 : 0
            print r "\t" n "\t" substr($0, 3) }' <<< "$raw" \
        | sort -t$'\t' -k1,1n -k4,4 -k2,2nr -k6,6 | cut -f3-)
    mapfile -t IPS    < <(awk '/^I\t/ { print substr($0, 3) }' <<< "$raw")
    mapfile -t USERS  < <(awk '/^U\t/ { print substr($0, 3) }' <<< "$raw")
    mapfile -t LOGINS < <(awk '/^L\t/ { print substr($0, 3) }' <<< "$raw")
    if [[ ${#ALERTS[@]} -gt 0 ]]; then
        WORST_SEV=${ALERTS[0]%%$'\t'*}            # ya están ordenadas por severidad
        WORST=$(sev_num "$WORST_SEV")
    fi
    BLOCK=$(compute_block_ips)
    [[ ${#IPS[@]} -gt 0 ]] && mapfile -t IPS < <(printf '%s\n' "${IPS[@]}" | sort -t$'\t' -k2,2nr -k1,1)
    [[ ${#USERS[@]} -gt 0 ]] && mapfile -t USERS < <(printf '%s\n' "${USERS[@]}" | sort -t$'\t' -k2,2nr -k1,1)
}

# IPs que merecen bloqueo: las que dispararon fuerza bruta, spraying o intrusión,
# excepto el propio equipo y la IP desde la que estás conectado.
# Se calcula una sola vez con awk (con miles de alertas, un bucle de bash
# lanzando subprocesos por alerta tardaba minutos).
BLOCK=""
compute_block_ips() {
    [[ ${#ALERTS[@]} -eq 0 ]] && return 0
    printf '%s\n' "${ALERTS[@]}" | awk -F'\t' -v me="$MY_IP" '
        $2 == "SSH-BRUTE" || $2 == "SSH-SPRAY" || $2 == "SSH-COMPROMISE" {
            ip = $4
            # Solo IPs válidas: IPv4 con 4 números o IPv6 (hex y ":")
            if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                split(ip, o, "."); if (o[1] > 255 || o[2] > 255 || o[3] > 255 || o[4] > 255) next
            } else if (ip !~ /^[0-9A-Fa-f:.]+$/ || ip !~ /:/ || ip !~ /[1-9A-Fa-f]/ || length(ip) > 45) next
            if (ip ~ /^127\./ || ip == "::1" || ip ~ /^::ffff:127\./) next        # el propio equipo
            if (me != "" && ip == me) next                                         # tu conexión
            if (!seen[ip]++) print ip
        }'
}
block_ips() { [[ -n "$BLOCK" ]] && printf '%s\n' "$BLOCK"; return 0; }

# Firewall para los comandos sugeridos: el indicado, o el que esté instalado.
detect_firewall() {
    [[ -n "$FIREWALL" ]] && return 0
    if have ufw; then FIREWALL=ufw
    elif have firewall-cmd; then FIREWALL=firewalld
    else FIREWALL=ufw; fi
}

# Comando de bloqueo.
#  · UFW aplica la PRIMERA regla que coincide: un "deny" agregado al final,
#    después de un "allow 22", nunca se aplicaría. "ufw prepend" lo pone el
#    primero, funciona aunque no haya reglas ("insert 1" falla en ese caso;
#    comprobado en ufw 0.36.2) y coloca cada regla en su lista IPv4 o IPv6.
#  · firewalld: la zona "drop" descarta todo lo que venga de esa IP.
block_cmd() {
    case "$FIREWALL" in
        firewalld) printf 'firewall-cmd --permanent --zone=drop --add-source=%s' "$1" ;;
        *)         printf 'ufw prepend deny from %s comment ssh-sentinel' "$1" ;;
    esac
}

svc_active() { have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }

render_text() {
    local c=${1:-0} b="" x="" g="" y="" r="" i
    [[ $c -eq 1 ]] && { b=$C_BLD; x=$C_RST; g=$C_GRY; y=$C_GRN; r=$C_RED; }
    printf '%sssh-sentinel v%s%s — análisis de ataques contra SSH\n' "$b" "$VERSION" "$x"
    printf '%sOrigen: %s%s\n' "$g" "$SOURCE_DESC" "$x"
    if [[ "${SUM[tmin]:-0}" != 0 ]]; then
        printf '%sPeriodo: %s → %s%s\n' "$g" "$(fmt_time "${SUM[tmin]}")" "$(fmt_time "${SUM[tmax]}")" "$x"
    fi

    printf '\n%s== Resumen ==%s\n' "$b" "$x"
    printf '  Intentos fallidos: %s · Accesos exitosos: %s · IPs con fallos: %s\n' \
        "${SUM[fails]:-0}" "${SUM[oks]:-0}" "${SUM[ips]:-0}"

    printf '\n%s== Alertas ==%s\n' "$b" "$x"
    if [[ ${#ALERTS[@]} -eq 0 ]]; then
        printf '  %sSin alertas.%s No se detectaron ataques con los umbrales actuales.\n' "$y" "$x"
    else
        # En un ataque de una botnet puede haber miles de alertas iguales: se
        # muestran las 5 más grandes de cada tipo y un resumen del resto.
        local sev id title ip t mitre col="" per=5
        if [[ ${#ALERTS[@]} -gt 10 ]]; then
            printf '  %d alertas en total: %s\n' "${#ALERTS[@]}" \
                "$(printf '%s\n' "${ALERTS[@]}" | awk -F'\t' '!($2 in n) { o[++k] = $2 } { n[$2]++ } END { for (i = 1; i <= k; i++) printf "%s%s=%d", (i > 1 ? ", " : ""), o[i], n[o[i]] }')"
            printf '  %sSe muestran hasta %d por tipo; el informe JSON (--format json) las incluye todas.%s\n\n' "$g" "$per" "$x"
        fi
        while IFS=$'\t' read -r sev id title ip t mitre; do
            if [[ "$sev" == MORE ]]; then
                printf '  %s%-10s %-17s … y %s alertas %s más%s\n' "$g" "" "" "$title" "$id" "$x"
                continue
            fi
            [[ $c -eq 1 ]] && col=$(sev_color "$sev")
            printf '  %s%-10s%s %-17s %s\n' "$col" "[$(sev_label "$sev" | sed 's/Í/I/')]" "$x" "$id" "$title"
            local det=""
            [[ "$ip" != "-" ]] && det="IP $ip"
            [[ "$t" != 0 ]] && det+="${det:+ · }$(fmt_time "$t")"
            [[ "$id" == SSH-PASSWORD ]] && det="Usuarios: ${SUM[pwusers]//,/, }"
            printf '  %s%-10s %-17s %s · MITRE %s%s\n' "$g" "" "" "$det" "$mitre" "$x"
        done < <(printf '%s\n' "${ALERTS[@]}" | awk -F'\t' -v per="$per" '
            function more() { if (cnt > per) printf "MORE\t%s\t%d\n", prev, cnt - per }
            $1 SUBSEP $2 != prev_key { more(); cnt = 0; prev_key = $1 SUBSEP $2; prev = $2 }
            { if (++cnt <= per) print }
            END { more() }')
    fi

    if [[ ${#IPS[@]} -gt 0 ]]; then
        printf '\n%s== Top %d IPs con intentos fallidos ==%s\n' "$b" "$TOP" "$x"
        printf '  %-20s %7s %6s %9s %7s  %s\n' "IP" "Fallos" "Pico*" "Usuarios" "Acceso" "Usuarios probados"
        local ip f nu mw ok ul
        for i in "${IPS[@]:0:$TOP}"; do
            IFS=$'\t' read -r ip f nu _ _ mw ok ul <<< "$i"
            printf '  %-20s %7s %6s %9s %7s  %s\n' "$ip" "$f" "$mw" "$nu" "$([[ $ok -gt 0 ]] && echo SI || echo no)" "${ul//,/, }"
        done
        printf '  %s* Pico: máximo de fallos dentro de una ventana de %d minutos. Acceso: si esa IP llegó a entrar.%s\n' "$g" "$WINDOW_MIN" "$x"
    fi

    if [[ ${#USERS[@]} -gt 0 ]]; then
        printf '\n%s== Top %d usuarios con intentos fallidos ==%s\n' "$b" "$TOP" "$x"
        local u n ni
        for i in "${USERS[@]:0:$TOP}"; do
            IFS=$'\t' read -r u n ni <<< "$i"
            printf '  %-24s %6s intento(s) desde %5s IP(s)%s\n' "$u" "$n" "$ni" "$([[ "$u" == root ]] && echo "  <- cuenta de administrador")"
        done
    fi

    if [[ ${#LOGINS[@]} -gt 0 ]]; then
        printf '\n%s== Accesos exitosos (últimos %d) ==%s\n' "$b" "$TOP" "$x"
        local t u ip me pf
        local start=$(( ${#LOGINS[@]} > TOP ? ${#LOGINS[@]} - TOP : 0 ))
        for i in "${LOGINS[@]:$start}"; do
            IFS=$'\t' read -r t u ip me pf <<< "$i"
            printf '  %s  %-14s desde %-18s con %-10s%s\n' "$(fmt_time "$t")" "$u" "$ip" "$me" \
                "$([[ $pf -gt 0 ]] && echo " (tras $pf fallos de esa IP)")"
        done
    fi

    # --- Prevención ---
    printf '\n%s== Prevención recomendada ==%s\n' "$b" "$x"
    local blk n=0
    blk=$(block_ips)
    if [[ -n "$blk" ]]; then
        printf '  1. Bloquear las IPs atacantes (revísalas antes de aplicar):\n'
        while IFS= read -r i; do
            printf '     sudo %s%s\n' "$(block_cmd "$i")" "$(is_private "$i" && echo "   <- red interna: revisa ese equipo, puede estar comprometido")"
            n=$((n + 1)); [[ $n -ge 15 ]] && { printf '     … (usa --block-script para la lista completa)\n'; break; }
        done <<< "$blk"
        [[ "$FIREWALL" == firewalld ]] && printf '     sudo firewall-cmd --reload\n'
    fi
    local ip skipped="" alert_ips
    alert_ips=$(printf '%s\n' "${ALERTS[@]}" | cut -f4 | sort -u)
    ip=$(grep -m1 -E '^(127\.|::1$|::ffff:127\.)' <<< "$alert_ips")
    [[ -n "$ip" ]] && skipped="$ip: es el propio equipo. Investiga qué proceso local generó los intentos"
    if [[ -n "$MY_IP" ]] && grep -qxF -- "$MY_IP" <<< "$alert_ips"; then
        skipped="$MY_IP: es tu conexión actual. Si esos intentos no fueron tuyos, cambia tus contraseñas"
    fi
    [[ -n "$skipped" ]] && printf '  %sNo se sugiere bloquear %s.%s\n' "$g" "$skipped" "$x"
    local k=2; [[ -z "$blk" ]] && k=1
    if ! svc_active fail2ban && ! svc_active crowdsec; then
        printf '  %d. Bloqueo automático: sudo apt install fail2ban && sudo systemctl enable --now fail2ban\n' "$k"; k=$((k + 1))
    fi
    if [[ -n "${SUM[pwusers]:-}" ]] || [[ "${SUM[fails]:-0}" -gt 0 ]]; then
        printf '  %d. Usar llaves SSH y desactivar contraseñas (ssh-copy-id, luego PasswordAuthentication no)\n' "$k"; k=$((k + 1))
    fi
    if printf '%s\n' "${USERS[@]}" | grep -q '^root'$'\t'; then
        printf '  %d. Impedir el acceso directo de root: PermitRootLogin no\n' "$k"; k=$((k + 1))
    fi
    if printf '%s\n' "${ALERTS[@]}" | grep -q 'SSH-DISTRIBUTED'; then
        printf '  %d. Ataque distribuido: bloquear IP por IP no sirve. Desactiva las contraseñas\n' "$k"
        printf '     (PasswordAuthentication no) o limita SSH a tus redes (AllowUsers usuario@red, VPN).\n'
        k=$((k + 1))
    fi
    if printf '%s\n' "${ALERTS[@]}" | grep -q 'SSH-SUSPECT-LOGIN'; then
        printf '  %d. Confirma con el dueño de la cuenta que el acceso con contraseña fue suyo;\n' "$k"
        printf '     si no, trátalo como intrusión y cambia la contraseña.\n'
        k=$((k + 1))
    fi
    if printf '%s\n' "${ALERTS[@]}" | grep -q 'SSH-COMPROMISE'; then
        printf '  %s%d. URGENTE: hubo un acceso tras muchos fallos. Cambia la contraseña de esa cuenta,%s\n' "$r" "$k" "$x"
        printf '     revisa qué hizo (last, journalctl _UID=...) y trátalo como un incidente.\n'
    fi
    [[ $k -eq 1 && -z "$blk" ]] && printf '  Nada urgente. Mantén SSH con llaves y fail2ban activo.\n'
    echo
}

# Funciones awk para el JSON: formatear fechas y escapar texto en UNA sola
# pasada. (Antes se lanzaban 'date' y 'tr' por cada IP: con 17.000 IPs el
# informe tardaba más de 3 minutos; así tarda menos de 1 segundo.)
read -r -d '' JSONLIB_AWK <<'AWK' || true  # read -d '' devuelve 1 al llegar al final: es normal
function civil(z,    era, doe, yoe, doy, mp, d, m, y) {
    z += 719468
    era = int((z >= 0 ? z : z - 146096) / 146097)
    doe = z - era * 146097
    yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
    y = yoe + era * 400
    doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
    mp = int((5 * doy + 2) / 153)
    d = doy - int((153 * mp + 2) / 5) + 1
    m = mp + (mp < 10 ? 3 : -9)
    return sprintf("%04d-%02d-%02d", y + (m <= 2), m, d)
}
function fmt(e,    s) {
    if (e == "" || e == 0) return ""
    s = e % 86400
    return civil(int(e / 86400)) sprintf(" %02d:%02d:%02d", int(s / 3600), int(s % 3600 / 60), s % 60)
}
function esc(v) {
    gsub(/\\/, "\\\\", v); gsub(/"/, "\\\"", v)
    gsub(/\t/, "\\t", v); gsub(/\r/, "\\r", v); gsub(ctrl, "", v)
    return v
}
BEGIN { FS = "\t"; ctrl = sprintf("[%c-%c]", 1, 31) }
AWK

# Convierte registros TSV en objetos JSON separados por comas
json_rows() {
    awk "$JSONLIB_AWK"'
        { printf "%s\n    ", (NR > 1 ? "," : "") }
        kind == "alert" { printf "{\"severity\": \"%s\", \"id\": \"%s\", \"title\": \"%s\", \"ip\": \"%s\", \"time\": \"%s\", \"mitre\": \"%s\"}", $1, $2, esc($3), esc($4), fmt($5), esc($6) }
        kind == "ip"    { printf "{\"ip\": \"%s\", \"failed\": %d, \"max_in_window\": %d, \"users\": %d, \"accepted\": %d, \"first\": \"%s\", \"last\": \"%s\", \"usernames\": \"%s\"}", esc($1), $2, $6, $3, $7, fmt($4), fmt($5), esc($8) }
        kind == "user"  { printf "{\"user\": \"%s\", \"attempts\": %d, \"ips\": %d}", esc($1), $2, $3 }
        kind == "login" { printf "{\"time\": \"%s\", \"user\": \"%s\", \"ip\": \"%s\", \"method\": \"%s\", \"failed_before\": %d}", fmt($1), esc($2), esc($3), esc($4), $5 }
        END { if (NR > 0) printf "\n  " }' kind="$1"
}

render_json() {
    printf '{\n  "tool": "ssh-sentinel",\n  "version": "%s",\n' "$VERSION"
    printf '  "host": "%s",\n  "generated": "%s",\n' "$(json_esc "${HOSTNAME:-}")" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "source": "%s",\n' "$(json_esc "$SOURCE_DESC")"
    printf '  "period": {"from": "%s", "to": "%s"},\n' "$(fmt_time "${SUM[tmin]:-0}")" "$(fmt_time "${SUM[tmax]:-0}")"
    printf '  "thresholds": {"threshold": %d, "window_min": %d, "spray": %d, "after_fail": %d, "distributed": %d},\n' \
        "$THRESHOLD" "$WINDOW_MIN" "$SPRAY" "$AFTER_FAIL" "$DIST"
    printf '  "summary": {"failed": %d, "accepted": %d, "attacking_ips": %d, "alerts": %d, "worst": "%s"},\n' \
        "${SUM[fails]:-0}" "${SUM[oks]:-0}" "${SUM[ips]:-0}" "${#ALERTS[@]}" "$WORST_SEV"
    printf '  "firewall": "%s",\n' "$FIREWALL"
    printf '  "alerts": ['
    [[ ${#ALERTS[@]} -gt 0 ]] && printf '%s\n' "${ALERTS[@]}" | json_rows alert
    printf '],\n  "ips": ['
    [[ ${#IPS[@]} -gt 0 ]] && printf '%s\n' "${IPS[@]}" | json_rows ip
    printf '],\n  "users": ['
    [[ ${#USERS[@]} -gt 0 ]] && printf '%s\n' "${USERS[@]:0:100}" | json_rows user
    printf '],\n  "logins": ['
    [[ ${#LOGINS[@]} -gt 0 ]] && printf '%s\n' "${LOGINS[@]}" | json_rows login
    printf '],\n  "block_suggestions": ['
    local ip first=1
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        [[ $first -eq 1 ]] && first=0 || printf ', '
        printf '"%s"' "$ip"
    done <<< "$(block_ips)"
    printf ']\n}\n'
}

# Rutas de salida: se validan AL INICIO, en el proceso principal. Si se
# comprobaran dentro de una tubería, un error solo cerraría ese subproceso.
check_dest() {
    local dest=$1 dir
    [[ -L "$dest" ]] && die "$dest es un enlace simbólico; por seguridad no se escribe en él"
    [[ -d "$dest" ]] && die "$dest es un directorio"
    dir=$(dirname -- "$dest")
    [[ -d "$dir" && -w "$dir" ]] || die "no se puede escribir en el directorio $dir"
}

# Escritura segura y atómica (mismo método que linux-audit)
safe_write() {
    local dest=$1 tmp
    tmp=$(mktemp -- "$(dirname -- "$dest")/.ssh-sentinel.XXXXXX") || die "no se puede escribir en $(dirname -- "$dest")"
    cat > "$tmp"
    mv -f -T -- "$tmp" "$dest" || { rm -f -- "$tmp"; die "no se pudo guardar $dest"; }
}

# Script de bloqueo para que una persona lo revise y lo ejecute.
# shellcheck disable=SC2016  # los "$1" deben quedar literales en el script generado
write_block_script() {
    local ips
    ips=$(block_ips)
    {
        printf '#!/bin/sh\n'
        printf '# Bloqueos sugeridos por ssh-sentinel v%s — %s — %s\n' "$VERSION" "${HOSTNAME:-}" "$(date '+%Y-%m-%d %H:%M')"
        printf '# REVÍSALO ANTES DE EJECUTARLO: asegúrate de no bloquear tu propia IP.\n'
        printf '# Ejecutar con: sudo sh %s\n' "$(basename -- "$BLOCK_SCRIPT")"
        if [[ "$FIREWALL" == firewalld ]]; then
            printf '# Deshacer un bloqueo: sudo firewall-cmd --permanent --zone=drop --remove-source=IP && sudo firewall-cmd --reload\n\n'
            printf 'firewall-cmd --state >/dev/null 2>&1 || { echo "firewalld no está activo"; exit 1; }\n\n'
            printf 'bloquear() {\n    firewall-cmd --permanent --zone=drop --add-source="$1" >/dev/null || echo "No se pudo bloquear $1"\n}\n\n'
        else
            printf '# Deshacer un bloqueo: sudo ufw delete deny from IP\n\n'
            printf 'LC_ALL=C ufw status | grep -q "Status: active" || { echo "UFW no está activo: sudo ufw enable"; exit 1; }\n\n'
            printf '# "prepend" pone el bloqueo ANTES de cualquier "allow" (UFW aplica la primera\n'
            printf '# regla que coincide). Funciona con IPv4 e IPv6 y aunque no haya reglas.\n'
            printf 'bloquear() {\n    ufw prepend deny from "$1" comment ssh-sentinel || echo "No se pudo bloquear $1"\n}\n\n'
        fi
        if [[ -z "$ips" ]]; then
            printf '# No hay IPs que bloquear.\n'
        else
            awk '{ p = ($0 ~ /^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|[fF][cCdD]|[fF][eE]80:)/)
                   print "bloquear " $0 (p ? "   # red interna: revisa ese equipo" : "") }' <<< "$ips"
            [[ "$FIREWALL" == firewalld ]] && printf '\nfirewall-cmd --reload\n'
        fi
    } | safe_write "$BLOCK_SCRIPT"
    chmod 700 -- "$BLOCK_SCRIPT"
}

# =============================================================================
#  Configuración
#  /etc/ssh-sentinel/ssh-sentinel.conf, con líneas CLAVE=valor. Se lee como
#  texto (nunca con 'source') y cada valor pasa por la MISMA validación que la
#  línea de comandos, que además tiene prioridad sobre el archivo.
# =============================================================================
CONF_ARGS=()
load_config() {
    local f=$1 line key val opt n=0
    [[ -L "$f" ]] && die "$f es un enlace simbólico; por seguridad no se usa"
    [[ -f "$f" && -r "$f" ]] || die "no se puede leer la configuración $f"
    # Quien pueda modificar este archivo puede ocultar ataques (con IGNORE)
    if [[ -n "$(find "$f" -maxdepth 0 -perm /022 2>/dev/null)" ]]; then
        die "$f puede ser modificado por otros usuarios. Usa: sudo chmod 644 $f"
    fi
    if [[ $EUID -eq 0 && "$(stat -c %u -- "$f")" != 0 ]]; then
        die "$f debe pertenecer a root. Usa: sudo chown root:root $f"
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1)); line=${line%$'\r'}
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        [[ "$line" =~ ^[[:space:]]*([A-Z_]+)[[:space:]]*=[[:space:]]*(.*)$ ]] \
            || die "$f, línea $n: formato no válido (usa CLAVE=valor)"
        key=${BASH_REMATCH[1]}; val=${BASH_REMATCH[2]}
        [[ "$val" =~ ^(.*[^[:space:]])?[[:space:]]+#.*$ ]] && val=${BASH_REMATCH[1]}   # comentario al final
        [[ "$val" == "#"* ]] && val=""
        val=${val%"${val##*[![:space:]]}"}          # espacios al final
        if [[ "$val" == \"*\" || "$val" == \'*\' ]]; then val=${val:1:${#val}-2}; fi
        [[ -z "$val" ]] && continue                 # CLAVE= vacío: valor por defecto
        case "$key" in
            THRESHOLD)       opt=--threshold ;;
            WINDOW)          opt=--window ;;
            SPRAY)           opt=--spray ;;
            AFTER_FAIL)      opt=--after-fail ;;
            DISTRIBUTED)     opt=--distributed ;;
            TOP)             opt=--top ;;
            IGNORE)          opt=--ignore ;;
            FAIL_ON)         opt=--fail-on ;;
            FIREWALL)        opt=--firewall ;;
            TELEGRAM_CONFIG) opt=--telegram-config ;;
            TELEGRAM_RATE)   opt=--telegram-rate ;;
            TELEGRAM)
                case "${val,,}" in
                    yes|si|true|1) CONF_ARGS+=(--telegram) ;;
                    no|false|0)    ;;
                    *) die "$f, línea $n: TELEGRAM debe ser yes o no" ;;
                esac
                continue ;;
            *) die "$f, línea $n: clave desconocida '$key'" ;;
        esac
        CONF_ARGS+=("$opt" "$val")
    done < "$f"
}

# =============================================================================
#  Programa principal
# =============================================================================
is_uint() { [[ "$1" =~ ^[0-9]+$ && "$1" -gt 0 && ${#1} -le 9 ]]; }

# Lista de IPs de confianza. Cada elemento debe ser una IP completa, una red
# CIDR IPv4 o un prefijo que termine en "." o ":". Así "--ignore 1" o
# "192.168.1" no ocultan por error medio internet (192.168.1 = 192.168.100-199...).
valid_ignore() {
    local e list net bits
    [[ "$1" =~ ^[0-9A-Fa-f:.,/]+$ ]] || return 1
    IFS=, read -r -a list <<< "$1"
    for e in "${list[@]}"; do
        [[ -z "$e" ]] && continue
        if [[ "$e" == */* ]]; then
            [[ "$e" =~ ^([0-9.]+)/([0-9]{1,2})$ ]] || return 1
            net=${BASH_REMATCH[1]}; bits=${BASH_REMATCH[2]}     # valid_ip cambia BASH_REMATCH
            valid_ip "$net" && (( 10#$bits <= 32 )) || return 1
        elif [[ "$e" =~ ^([0-9]{1,3}\.){1,3}$ || "$e" =~ ^[0-9A-Fa-f:]*:$ ]]; then
            continue                                            # prefijo
        else
            valid_ip "$e" || return 1                           # IP completa
        fi
    done
    return 0
}

NO_TG=0
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--file)        [[ -n "${2:-}" ]] || die "--file necesita un archivo"
                              [[ -r "$2" && ! -d "$2" ]] || die "no se puede leer $2"; FILES+=("$2"); shift 2 ;;
            --since)          [[ -n "${2:-}" ]] || die "--since necesita un valor"; SINCE=$2; SINCE_SET=1; shift 2 ;;
            --threshold)      is_uint "${2:-}" || die "--threshold necesita un número"; THRESHOLD=$2; shift 2 ;;
            --window)         is_uint "${2:-}" || die "--window necesita un número de minutos"; WINDOW_MIN=$2; shift 2 ;;
            --spray)          is_uint "${2:-}" || die "--spray necesita un número"; SPRAY=$2; shift 2 ;;
            --after-fail)     is_uint "${2:-}" || die "--after-fail necesita un número"; AFTER_FAIL=$2; shift 2 ;;
            --distributed)    is_uint "${2:-}" || die "--distributed necesita un número"; DIST=$2; shift 2 ;;
            --top)            is_uint "${2:-}" || die "--top necesita un número"; TOP=$2; shift 2 ;;
            --ignore)         valid_ignore "${2:-}" || die "--ignore solo acepta IPs, prefijos o redes CIDR IPv4 separados por comas"
                              IGNORE=$2; shift 2 ;;
            --format)         [[ "${2:-}" =~ ^(text|json)$ ]] || die "--format debe ser text o json"; FORMAT=$2; shift 2 ;;
            -o|--output)      [[ -n "${2:-}" ]] || die "--output necesita un archivo"; OUTPUT_FILE=$2; shift 2 ;;
            --block-script|--ufw-script)
                              [[ -n "${2:-}" ]] || die "$1 necesita un archivo"; BLOCK_SCRIPT=$2; shift 2 ;;
            --firewall)       [[ "${2:-}" =~ ^(ufw|firewalld)$ ]] || die "--firewall debe ser ufw o firewalld"; FIREWALL=$2; shift 2 ;;
            --fail-on)        [[ "${2:-}" =~ ^(low|medium|high|critical)$ ]] || die "--fail-on: low|medium|high|critical"
                              FAIL_ON=$2; shift 2 ;;
            --follow)         FOLLOW=1; shift ;;
            --telegram)       TELEGRAM=1; shift ;;
            --no-telegram)    NO_TG=1; shift ;;
            --telegram-config) [[ -n "${2:-}" ]] || die "--telegram-config necesita un archivo"; TG_CONFIG=$2; shift 2 ;;
            --telegram-rate)  is_uint "${2:-}" || die "--telegram-rate necesita un número"; TG_RATE=$2; shift 2 ;;
            --dry-run)        DRY_RUN=1; shift ;;
            --no-color)       USE_COLOR=0; shift ;;
            --config)         [[ -n "${2:-}" ]] || die "--config necesita un archivo"; shift 2 ;;  # ya leído en main
            --no-config)      shift ;;
            -h|--help)        usage; exit 0 ;;
            -v|--version)     echo "ssh-sentinel v${VERSION}"; exit 0 ;;
            *) printf 'Opción desconocida: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
        esac
    done
    [[ $NO_TG -eq 1 ]] && TELEGRAM=0
    [[ -n "$OUTPUT_FILE" ]] && check_dest "$OUTPUT_FILE"
    [[ -n "$BLOCK_SCRIPT" ]] && check_dest "$BLOCK_SCRIPT"
    if [[ -n "$OUTPUT_FILE" && -n "$BLOCK_SCRIPT" ]] \
       && { [[ "$OUTPUT_FILE" == "$BLOCK_SCRIPT" ]] || [[ "$OUTPUT_FILE" -ef "$BLOCK_SCRIPT" ]]; }; then
        die "el informe y el script de bloqueo no pueden ser el mismo archivo"
    fi
    return 0
}

main() {
    # La configuración se lee antes que las opciones, para que estas manden
    local a prev="" cfg="" nocfg=0
    for a in "$@"; do
        [[ "$prev" == --config ]] && cfg=$a
        [[ "$a" == --no-config ]] && nocfg=1
        prev=$a
    done
    if [[ $nocfg -eq 0 ]]; then
        if [[ -n "$cfg" ]]; then load_config "$cfg"
        elif [[ -e "$CONFIG_FILE" ]]; then load_config "$CONFIG_FILE"; fi
    fi
    parse_args ${CONF_ARGS[@]+"${CONF_ARGS[@]}"} "$@"
    NOW_S=${SSH_SENTINEL_NOW:-$(date '+%Y %m %d %H:%M:%S')}   # SSH_SENTINEL_NOW: solo para pruebas
    setup_colors
    [[ $TELEGRAM -eq 1 ]] && load_telegram

    if [[ $FOLLOW -eq 1 ]]; then
        run_follow
        exit $?
    fi

    if [[ ${#FILES[@]} -eq 0 && $EUID -ne 0 ]]; then
        printf 'Aviso: sin sudo es probable que no puedas leer los registros de SSH.\n\n' >&2
    fi

    detect_my_ip
    detect_firewall
    pick_source
    if [[ "$SOURCE_KIND" == none ]]; then
        die "no se encontraron registros de SSH (¿está instalado? prueba con sudo o con -f ARCHIVO)"
    fi
    resolve_since
    analyze

    case "$FORMAT" in
        text)
            if [[ -n "$OUTPUT_FILE" ]]; then
                render_text 0 | safe_write "$OUTPUT_FILE"
                printf 'Informe guardado en %s (permisos 600)\n' "$OUTPUT_FILE"
            else
                render_text "$USE_COLOR"
            fi ;;
        json)
            if [[ -n "$OUTPUT_FILE" ]]; then render_json | safe_write "$OUTPUT_FILE"
            else render_json; fi ;;
    esac

    if [[ -n "$BLOCK_SCRIPT" ]]; then
        write_block_script
        printf 'Script de bloqueo para revisar: %s (no se ha ejecutado)\n' "$BLOCK_SCRIPT" >&2
    fi

    if [[ $TELEGRAM -eq 1 && $WORST -ge $(sev_num "$FAIL_ON") ]]; then
        local msg al sev id title ip
        msg="🚨 ssh-sentinel en ${HOSTNAME:-?}"
        for al in "${ALERTS[@]:0:8}"; do
            IFS=$'\t' read -r sev id title ip _ <<< "$al"
            [[ "$ip" == - ]] && ip=""
            [[ $(sev_num "$sev") -ge $(sev_num "$FAIL_ON") ]] && msg+=$'\n'"$(sev_label "$sev") · ${title:0:200}${ip:+ · $ip}"
        done
        [[ ${#ALERTS[@]} -gt 8 ]] && msg+=$'\n'"(y $(( ${#ALERTS[@]} - 8 )) alertas más en el informe)"
        send_telegram "$msg"
    fi

    [[ $WORST -ge $(sev_num "$FAIL_ON") ]] && exit 1
    exit 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
