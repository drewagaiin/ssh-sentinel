#!/usr/bin/env bats
# Pruebas de ssh-sentinel. Son de solo lectura: se pueden correr en cualquier equipo.
#   bats tests/sentinel.bats

setup() {
    S="$BATS_TEST_DIRNAME/../ssh-sentinel.sh"
    F="$BATS_TEST_DIRNAME/fixtures"
    TMP="$(mktemp -d)"
}
teardown() { rm -rf "$TMP"; }

json() { "$S" "$@" --format json; }

# --- Interfaz -----------------------------------------------------------------

@test "--version y --help" {
    run "$S" --version; [ "$status" -eq 0 ]; [[ "$output" == ssh-sentinel\ v* ]]
    run "$S" --help;    [ "$status" -eq 0 ]; [[ "$output" == *"--follow"* ]]
}

@test "opciones inválidas devuelven código 2" {
    run "$S" --nada;                    [ "$status" -eq 2 ]
    run "$S" --threshold cero;          [ "$status" -eq 2 ]
    run "$S" --window 0;                [ "$status" -eq 2 ]
    run "$S" --format xml;              [ "$status" -eq 2 ]
    run "$S" --fail-on enorme;          [ "$status" -eq 2 ]
    run "$S" -f /no/existe.log;         [ "$status" -eq 2 ]
    run "$S" --ignore '1.2.3.4;reboot'; [ "$status" -eq 2 ]
}

# --- Conteo exacto ------------------------------------------------------------

@test "syslog: cuenta exacta de intentos, accesos e IPs" {
    run json -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '.summary.failed == 33 and .summary.accepted == 2 and .summary.attacking_ips == 4'
}

@test "un usuario inexistente cuenta UNA vez (Invalid user + Failed password)" {
    run json -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '.ips[] | select(.ip=="198.51.100.7") | .failed == 6 and .users == 6'
}

@test "'message repeated N times' de rsyslog se cuenta N veces" {
    run json -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '.ips[] | select(.ip=="203.0.113.10") | .failed == 19'
}

@test "no cuenta fallos de llave pública ni líneas de otros programas" {
    run json -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '[.ips[].ip] | index("6.6.6.6") == null'
    echo "$output" | jq -e '[.ips[].ip] | index("10.0.0.5") == null'
}

@test "Kali/Debian 13: formato ISO y proceso sshd-session" {
    run json -f "$F/ataques-kali.log"
    echo "$output" | jq -e '.summary.failed == 29 and .summary.accepted == 2'
    echo "$output" | jq -e '[.alerts[].id] | sort == ["SSH-BRUTE","SSH-COMPROMISE","SSH-PASSWORD","SSH-SPRAY"]'
}

@test "ataque REAL registrado por rsyslog: 24 intentos y 1 acceso" {
    run json -f "$F/real-rsyslog.log"
    echo "$output" | jq -e '.summary.failed == 24 and .summary.accepted == 1'
    echo "$output" | jq -e '.ips[0].users == 8'
}

@test "acepta archivos comprimidos .gz (rotación de logs)" {
    gzip -c "$F/ataques-syslog.log" > "$TMP/auth.log.2.gz"
    run json -f "$TMP/auth.log.2.gz"
    echo "$output" | jq -e '.summary.failed == 33'
}

@test "seguridad: un nombre de usuario con 'from IP' no engaña sobre la IP real" {
    # Truco clásico: el atacante pone "x from 8.8.8.8 port 22" como usuario para
    # que se bloquee una IP inocente (un DNS, la puerta de enlace...)
    for i in $(seq 10 21); do
        echo "Oct  5 03:00:$i srv sshd[$i]: Failed password for invalid user x from 8.8.8.8 port 22 from 203.0.113.9 port 40$i ssh2"
    done > "$TMP/inj.log"
    run json -f "$TMP/inj.log"
    echo "$output" | jq -e '[.ips[].ip] == ["203.0.113.9"]'
    echo "$output" | jq -e '.block_suggestions == ["203.0.113.9"]'
}

@test "seguridad: el mismo engaño contra un OpenSSH 9.6 REAL no funciona" {
    # Registro real: OpenSSH guarda el nombre "x from 8.8.8.8 port 22" tal cual
    run json -f "$F/real-inyeccion.log"
    echo "$output" | jq -e '[.ips[].ip] == ["127.0.0.1"]'
    echo "$output" | jq -e '.summary.failed == 10 and .summary.accepted == 1'
}

@test "seguridad: descarta 'IPs' que no lo son y limita 'message repeated'" {
    printf '%s\n' \
      'Oct  5 03:00:01 srv sshd[1]: Failed password for root from evil.example port 22 ssh2' \
      'Oct  5 03:00:02 srv sshd[2]: Failed password for root from 999.1.1.1 port 22 ssh2' \
      'Oct  5 03:00:03 srv sshd[3]: message repeated 999999999 times: [ Failed password for root from 203.0.113.5 port 22 ssh2]' \
      'Oct  5 03:00:04 srv sshd[4]: Failed password for root from :: port 22 ssh2' \
      'Oct  5 03:00:05 srv otraapp[7]: nota sshd[1]: Failed password for root from 198.51.100.99 port 1 ssh2' \
      > "$TMP/raro.log"
    run timeout 60 "$S" -f "$TMP/raro.log" --format json
    echo "$output" | jq -e '[.ips[].ip] == ["203.0.113.5"] and .ips[0].failed == 100'
}

@test "seguridad: bytes no válidos en el usuario no rompen el JSON" {
    printf 'Oct  5 03:00:01 srv sshd[1]: Failed password for invalid user a\377\233b from 203.0.113.8 port 1 ssh2\n' > "$TMP/bin.log"
    run json -f "$TMP/bin.log"
    echo "$output" | jq -e '.users[0].user == "a??b"'
}

@test "IPv4 escrita como IPv6 (::ffff:1.2.3.4) se trata como IPv4" {
    echo 'Oct  5 03:00:01 srv sshd[1]: Failed password for root from ::ffff:203.0.113.77 port 1 ssh2' > "$TMP/m.log"
    run json -f "$TMP/m.log"
    echo "$output" | jq -e '.ips[0].ip == "203.0.113.77"'
}

@test "cambio de año: el 2 de enero, una línea del 31 de diciembre es del año anterior" {
    echo 'Dec 31 23:59:00 srv sshd[1]: Accepted password for bob from 198.51.100.1 port 1 ssh2' > "$TMP/y.log"
    SSH_SENTINEL_NOW="2027 01 02 10:00:00" run json -f "$TMP/y.log"
    echo "$output" | jq -e '.period.from == "2026-12-31 23:59:00"'
}

@test "un archivo dañado da error (código 2), no un informe 'sin alertas'" {
    echo basura > "$TMP/roto.gz"
    run "$S" -f "$TMP/roto.gz"
    [ "$status" -eq 2 ]
    [[ "$output" != *"Sin alertas"* ]]
}

@test "--since filtra por fecha y rechaza valores no válidos" {
    # Las fechas de syslog no traen año: se fija "hoy" para que la prueba no caduque
    SSH_SENTINEL_NOW="2026 10 06 12:00:00" run json -f "$F/ataques-syslog.log" --since "2026-10-05 04:00"
    echo "$output" | jq -e '.summary.failed == 8'
    run "$S" -f "$F/ataques-syslog.log" --since "cuando sea"
    [ "$status" -eq 2 ]
}

# --- Detecciones --------------------------------------------------------------

@test "detecta fuerza bruta (T1110.001)" {
    run json -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '.alerts[] | select(.id=="SSH-BRUTE") | .ip == "203.0.113.10" and .severity == "high" and .mitre == "T1110.001"'
}

@test "detecta password spraying lento que NO es fuerza bruta (T1110.003)" {
    run json -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '.alerts[] | select(.id=="SSH-SPRAY") | .ip == "198.51.100.7"'
    echo "$output" | jq -e '[.alerts[] | select(.id=="SSH-BRUTE" and .ip=="198.51.100.7")] | length == 0'
}

@test "detecta acceso exitoso tras fallos como CRÍTICO" {
    run json -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '.alerts[0] | .id == "SSH-COMPROMISE" and .severity == "critical" and .ip == "192.0.2.50"'
}

@test "detecta ataque distribuido: muchas IPs contra un mismo usuario" {
    run json -f "$F/distribuido.log"
    echo "$output" | jq -e '.alerts[] | select(.id=="SSH-DISTRIBUTED") | .severity == "medium" and (.title | test("admin"))'
    # Ninguna IP sola cruza los umbrales: por IP no se habría detectado nada
    echo "$output" | jq -e '[.alerts[] | select(.id=="SSH-BRUTE" or .id=="SSH-SPRAY")] | length == 0'
    run json -f "$F/distribuido.log" --distributed 30
    echo "$output" | jq -e '[.alerts[] | select(.id=="SSH-DISTRIBUTED")] | length == 0'
}

@test "detecta acceso con contraseña a una cuenta atacada desde otras IPs" {
    run json -f "$F/distribuido.log"
    echo "$output" | jq -e '.alerts[0] | .id == "SSH-SUSPECT-LOGIN" and .ip == "198.51.100.200" and .severity == "high"'
    # La IP que entró nunca falló: no se sugiere bloquearla a ciegas
    echo "$output" | jq -e '.block_suggestions | index("198.51.100.200") == null'
}

@test "con miles de alertas, el texto muestra 5 por tipo y resume el resto" {
    for ip in $(seq 1 12); do for s in $(seq 10 21); do
        echo "Oct  5 03:00:$s srv sshd[$ip$s]: Failed password for root from 203.0.113.$ip port 1$s ssh2"
    done; done > "$TMP/muchas.log"
    run "$S" -f "$TMP/muchas.log" --no-color
    [ "$(grep -c '\[ALTO\]     SSH-BRUTE' <<< "$output")" -eq 5 ]
    [[ "$output" == *"… y 7 alertas SSH-BRUTE más"* ]]
}

@test "los umbrales se pueden ajustar" {
    run json -f "$F/ataques-syslog.log" --threshold 50
    echo "$output" | jq -e '[.alerts[] | select(.id=="SSH-BRUTE")] | length == 0'
    run json -f "$F/ataques-syslog.log" --spray 10
    echo "$output" | jq -e '[.alerts[] | select(.id=="SSH-SPRAY")] | length == 0'
}

@test "--ignore excluye IPs por prefijo" {
    run json -f "$F/ataques-syslog.log" --ignore 203.0.113.,192.0.2.
    echo "$output" | jq -e '.summary.attacking_ips == 1 and .ips[0].ip == "198.51.100.7"'
}

@test "--ignore acepta redes CIDR e IPs exactas (10.0.0.5 no ignora 10.0.0.50)" {
    run json -f "$F/ataques-syslog.log" --ignore 203.0.113.0/24,192.0.2.0/25
    echo "$output" | jq -e '.summary.attacking_ips == 1'
    run json -f "$F/ataques-syslog.log" --ignore 203.0.113.1
    echo "$output" | jq -e '[.ips[].ip] | index("203.0.113.10") != null'
    # IPv6: una dirección completa es exacta; un prefijo termina en ":"
    printf 'Oct  5 03:00:01 srv sshd[1]: Failed password for root from 2001:db8::5ab port 1 ssh2\n' > "$TMP/v6.log"
    run json -f "$TMP/v6.log" --ignore 2001:db8::5
    echo "$output" | jq -e '.summary.attacking_ips == 1'
    run json -f "$TMP/v6.log" --ignore 2001:db8:
    echo "$output" | jq -e '.summary.attacking_ips == 0'
    run "$S" -f "$F/normal.log" --ignore 10.0.0.0/33; [ "$status" -eq 2 ]
    run "$S" -f "$F/normal.log" --ignore 10.0.0/8;    [ "$status" -eq 2 ]
    # Un prefijo debe terminar en "." o ":" (si no, "1" ocultaría medio internet)
    run "$S" -f "$F/normal.log" --ignore 1;           [ "$status" -eq 2 ]
    run "$S" -f "$F/normal.log" --ignore 192.168;     [ "$status" -eq 2 ]
}

@test "registro normal: sin alertas y código de salida 0" {
    run "$S" -f "$F/normal.log" --no-color
    [ "$status" -eq 0 ]
    [[ "$output" == *"Sin alertas"* ]]
}

@test "con ataques: código de salida 1 (útil para automatizar)" {
    run "$S" -f "$F/ataques-syslog.log" --no-color
    [ "$status" -eq 1 ]
    run "$S" -f "$F/ataques-syslog.log" --no-color --fail-on critical
    [ "$status" -eq 1 ]
    run "$S" -f "$F/ataques-kali.log" --ignore 192.0.2. --no-color --fail-on critical
    [ "$status" -eq 0 ]
}

# --- Prevención y seguridad -----------------------------------------------------

@test "nunca sugiere bloquear el propio equipo (127.0.0.1)" {
    run json -f "$F/real-rsyslog.log"
    echo "$output" | jq -e '.block_suggestions == []'
}

@test "no sugiere bloquear la IP desde la que estás conectado" {
    SSH_CLIENT="203.0.113.10 5555 22" run json -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '.block_suggestions | index("203.0.113.10") == null'
    echo "$output" | jq -e '.block_suggestions | length == 2'
}

@test "el script de bloqueo es válido, privado y no se ejecuta solo" {
    run "$S" -f "$F/ataques-syslog.log" --block-script "$TMP/bloqueos.sh" --firewall ufw
    [ -f "$TMP/bloqueos.sh" ]
    [ "$(stat -c %a "$TMP/bloqueos.sh")" = "700" ]
    sh -n "$TMP/bloqueos.sh"
    [ "$(grep -c '^bloquear ' "$TMP/bloqueos.sh")" -eq 3 ]
    # prepend: antes de cualquier "allow", con IPv4 e IPv6 y aunque no haya reglas
    grep -q 'ufw prepend deny from "$1"' "$TMP/bloqueos.sh"
}

@test "--ufw-script sigue funcionando (compatibilidad con v1.0)" {
    run "$S" -f "$F/ataques-syslog.log" --ufw-script "$TMP/b.sh"
    [ -x "$TMP/b.sh" ]
}

@test "firewalld: script con la zona drop y recarga" {
    run "$S" -f "$F/ataques-syslog.log" --block-script "$TMP/fw.sh" --firewall firewalld
    sh -n "$TMP/fw.sh"
    grep -q -- '--zone=drop --add-source="$1"' "$TMP/fw.sh"
    grep -q '^firewall-cmd --reload' "$TMP/fw.sh"
    run "$S" -f "$F/ataques-syslog.log" --firewall firewalld --no-color
    [[ "$output" == *"firewall-cmd --permanent --zone=drop --add-source=203.0.113.10"* ]]
}

@test "un registro manipulado no inyecta comandos en el script de bloqueo" {
    run "$S" -f "$F/malicioso.log" --ufw-script "$TMP/b.sh" --threshold 1 --spray 1 --after-fail 1
    ! grep -q 'reboot' "$TMP/b.sh"
    ! grep -q 'allow' <(grep '^bloquear' "$TMP/b.sh")
    run json -f "$F/malicioso.log" --threshold 1
    echo "$output" | jq -e . >/dev/null
}

@test "se niega a escribir sobre un enlace simbólico" {
    echo original > "$TMP/victima"; ln -s "$TMP/victima" "$TMP/enlace"
    run "$S" -f "$F/normal.log" -o "$TMP/enlace"
    [ "$status" -eq 2 ]
    [ "$(cat "$TMP/victima")" = original ]
}

@test "el informe se guarda con permisos 600" {
    run "$S" -f "$F/ataques-syslog.log" -o "$TMP/r.txt"
    [ "$(stat -c %a "$TMP/r.txt")" = "600" ]
    ! grep -q $'\e' "$TMP/r.txt"
}

# --- Modo en vivo y Telegram ----------------------------------------------------

@test "modo en vivo: emite cada alerta en el momento en que ocurre" {
    run "$S" --follow -f "$F/ataques-syslog.log" --no-color
    [[ "$output" == *"SSH-BRUTE"*"203.0.113.10"* ]]
    [[ "$output" == *"SSH-SPRAY"*"198.51.100.7"* ]]
    [[ "$output" == *"SSH-COMPROMISE"*"192.0.2.50"* ]]
    # La fuerza bruta se avisa al cruzar el umbral (intento 10), no al final
    [[ "$output" == *"03:01:12"*"SSH-BRUTE"* ]]
}

@test "Telegram: rechaza una configuración legible por otros" {
    printf 'TOKEN=123:abc\nCHAT_ID=1\n' > "$TMP/tg.conf"; chmod 644 "$TMP/tg.conf"
    run "$S" -f "$F/normal.log" --telegram --telegram-config "$TMP/tg.conf"
    [ "$status" -eq 2 ]; [[ "$output" == *"chmod 600"* ]]
}

@test "Telegram: valida el token (no permite inyección)" {
    printf 'TOKEN=1:abc; rm -rf /\nCHAT_ID=1\n' > "$TMP/tg.conf"; chmod 600 "$TMP/tg.conf"
    run "$S" -f "$F/normal.log" --telegram --telegram-config "$TMP/tg.conf"
    [ "$status" -eq 2 ]
}

@test "Telegram simulado: el mensaje incluye las alertas graves" {
    printf 'TOKEN=123456789:AAH-prueba_1\nCHAT_ID=987\n' > "$TMP/tg.conf"; chmod 600 "$TMP/tg.conf"
    command -v curl >/dev/null || skip "sin curl"
    run "$S" -f "$F/ataques-syslog.log" --telegram --telegram-config "$TMP/tg.conf" --dry-run
    [[ "$output" == *"[telegram simulado]"*"Acceso exitoso"* ]]
}

@test "Telegram en vivo: limita los mensajes pero las críticas se envían siempre" {
    printf 'TOKEN=123456789:AAH-prueba_1\nCHAT_ID=987\n' > "$TMP/tg.conf"; chmod 600 "$TMP/tg.conf"
    command -v curl >/dev/null || skip "sin curl"
    run "$S" --follow -f "$F/ataques-syslog.log" --no-color --telegram --telegram-config "$TMP/tg.conf" --dry-run --telegram-rate 1
    [ "$(grep -c 'telegram simulado' <<< "$output")" -eq 2 ]
    [[ "$output" == *"[telegram simulado]"*"SSH-COMPROMISE"*"no enviadas para no saturar"* ]]
}

@test "modo en vivo: también detecta ataques distribuidos" {
    run "$S" --follow -f "$F/distribuido.log" --no-color
    [[ "$output" == *"SSH-DISTRIBUTED"* ]]
    [[ "$output" == *"SSH-SUSPECT-LOGIN"*"198.51.100.200"* ]]
}

@test "fallos de hace más de 24 h no convierten un acceso en intrusión (informe y en vivo)" {
    {
        for s in $(seq 10 17); do echo "Oct  3 10:00:$s srv sshd[$s]: Failed password for bob from 203.0.113.44 port 1$s ssh2"; done
        echo "Oct  5 10:00:00 srv sshd[99]: Accepted password for bob from 203.0.113.44 port 2000 ssh2"
    } > "$TMP/viejo.log"
    run "$S" --follow -f "$TMP/viejo.log" --no-color
    [[ "$output" != *"SSH-COMPROMISE"* ]]
    run json -f "$TMP/viejo.log"
    echo "$output" | jq -e '[.alerts[] | select(.id=="SSH-COMPROMISE")] | length == 0'
}

@test "un error al escribir la contraseña cada día no es una intrusión" {
    for d in 1 2 3 4 5; do echo "Oct  $d 09:00:00 srv sshd[1$d]: Failed password for alice from 203.0.113.50 port 1$d ssh2"; done > "$TMP/typo.log"
    echo "Oct  5 09:00:30 srv sshd[99]: Accepted password for alice from 203.0.113.50 port 2000 ssh2" >> "$TMP/typo.log"
    run json -f "$TMP/typo.log"
    echo "$output" | jq -e '[.alerts[] | select(.severity=="critical" or .severity=="high")] | length == 0'
    echo "$output" | jq -e '.block_suggestions == []'
}

@test "errores propios de días anteriores desde otra IP no generan alerta" {
    for d in 1 2 3 4 5; do echo "Oct  $d 20:00:00 srv sshd[1$d]: Failed password for alice from 198.51.100.7 port 1$d ssh2"; done > "$TMP/n1.log"
    echo "Oct  6 09:00:00 srv sshd[99]: Accepted password for alice from 203.0.113.50 port 2000 ssh2" >> "$TMP/n1.log"
    SSH_SENTINEL_NOW="2026 10 06 12:00:00" run json -f "$TMP/n1.log"
    echo "$output" | jq -e '[.alerts[].id] == ["SSH-PASSWORD"]'
}

@test "rendimiento: 200.000 fallos de una IP y 200 accesos se analizan rápido" {
    awk 'BEGIN { for (i = 0; i < 200000; i++) { s = i % 3600; printf "Oct  5 10:%02d:%02d srv sshd[%d]: Failed password for root from 203.0.113.5 port %d ssh2\n", int(s / 60), s % 60, i, 1000 + i % 60000 }
                 for (j = 0; j < 200; j++) printf "Oct  5 11:%02d:%02d srv sshd[9%d]: Accepted publickey for deploy from 203.0.113.5 port %d ssh2: ED25519 SHA256:x\n", int(j / 60), j % 60, j, 2000 + j }' > "$TMP/grande.log"
    run timeout 60 "$S" -f "$TMP/grande.log" --format json
    echo "$output" | jq -e '.summary.failed == 200000 and .summary.accepted == 200'
}

@test "contraseña adivinada desde una IP y acceso desde OTRA: alerta" {
    for i in $(seq 10 39); do echo "Oct  5 03:00:$i srv sshd[$i]: Failed password for bob from 203.0.113.10 port 1$i ssh2"; done > "$TMP/dos.log"
    echo "Oct  5 03:05:00 srv sshd[99]: Accepted password for bob from 198.51.100.20 port 2000 ssh2" >> "$TMP/dos.log"
    run json -f "$TMP/dos.log"
    echo "$output" | jq -e '.alerts[] | select(.id=="SSH-SUSPECT-LOGIN") | .ip == "198.51.100.20"'
}

# --- Configuración -----------------------------------------------------------------

@test "configuración: aplica valores y la línea de comandos tiene prioridad" {
    printf '# prueba\nTHRESHOLD=50\nSPRAY = 10\nIGNORE="192.0.2.0/24"\n' > "$TMP/c.conf"; chmod 644 "$TMP/c.conf"
    run json --config "$TMP/c.conf" -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '.thresholds.threshold == 50 and .thresholds.spray == 10'
    echo "$output" | jq -e '[.ips[].ip] | index("192.0.2.50") == null'
    run json --config "$TMP/c.conf" -f "$F/ataques-syslog.log" --threshold 7
    echo "$output" | jq -e '.thresholds.threshold == 7'
}

@test "configuración: comentarios al final, comillas y valores vacíos (= por defecto)" {
    printf 'THRESHOLD=7   # mi valor\nSPRAY=%s\nFIREWALL=\nIGNORE=\n' "'6'" > "$TMP/c.conf"; chmod 644 "$TMP/c.conf"
    run json --config "$TMP/c.conf" -f "$F/ataques-syslog.log"
    echo "$output" | jq -e '.thresholds.threshold == 7 and .thresholds.spray == 6'
    # El ejemplo incluido en el proyecto debe funcionar tal cual
    cp "$BATS_TEST_DIRNAME/../config/ssh-sentinel.conf.example" "$TMP/ej.conf"; chmod 644 "$TMP/ej.conf"
    run "$S" --config "$TMP/ej.conf" -f "$F/normal.log"; [ "$status" -eq 0 ]
}

@test "configuración: rechaza archivos modificables por otros, claves desconocidas y valores inválidos" {
    printf 'THRESHOLD=5\n' > "$TMP/c.conf"; chmod 666 "$TMP/c.conf"
    run "$S" --config "$TMP/c.conf" -f "$F/normal.log"; [ "$status" -eq 2 ]
    printf 'NADA=1\n' > "$TMP/c.conf"; chmod 644 "$TMP/c.conf"
    run "$S" --config "$TMP/c.conf" -f "$F/normal.log"; [ "$status" -eq 2 ]
    printf 'THRESHOLD=$(touch %s/pwned)\n' "$TMP" > "$TMP/c.conf"
    run "$S" --config "$TMP/c.conf" -f "$F/normal.log"; [ "$status" -eq 2 ]
    [ ! -e "$TMP/pwned" ]
    ln -s "$F/normal.log" "$TMP/enlace.conf"
    run "$S" --config "$TMP/enlace.conf" -f "$F/normal.log"; [ "$status" -eq 2 ]
}

@test "instalador: instala con permisos correctos y desinstala" {
    mkdir "$TMP/raiz"
    run "$BATS_TEST_DIRNAME/../install.sh" --root "$TMP/raiz"
    [ "$status" -eq 0 ]
    [ "$(stat -c %a "$TMP/raiz/usr/local/bin/ssh-sentinel")" = 755 ]
    [ "$(stat -c %a "$TMP/raiz/etc/ssh-sentinel/ssh-sentinel.conf")" = 644 ]
    [ -f "$TMP/raiz/etc/systemd/system/ssh-sentinel.service" ]
    run "$TMP/raiz/usr/local/bin/ssh-sentinel" --config "$TMP/raiz/etc/ssh-sentinel/ssh-sentinel.conf" -f "$F/normal.log"
    [ "$status" -eq 0 ]
    run "$BATS_TEST_DIRNAME/../install.sh" --root "$TMP/raiz" --uninstall
    [ ! -e "$TMP/raiz/usr/local/bin/ssh-sentinel" ]
    [ -f "$TMP/raiz/etc/ssh-sentinel/ssh-sentinel.conf" ]
}

# --- Funciones internas -----------------------------------------------------------

@test "valid_ip rechaza texto que no es una IP" {
    source "$S"
    valid_ip 203.0.113.10
    valid_ip 2001:db8::1
    ! valid_ip '1.2.3.4;reboot'
    ! valid_ip 'abc'
    ! valid_ip '$(id)'
    ! valid_ip 999.1.1.1
    ! valid_ip 1.2.3
}

@test "is_private reconoce redes internas" {
    source "$S"
    is_private 10.1.2.3; is_private 192.168.0.5; is_private 172.20.0.1; is_private fd00::1
    ! is_private 172.32.0.1; ! is_private 8.8.8.8
}
