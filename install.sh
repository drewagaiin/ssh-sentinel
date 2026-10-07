#!/usr/bin/env bash
# =============================================================================
#  Instalador de ssh-sentinel
#
#    sudo ./install.sh              instala el programa, los servicios y la configuración
#    sudo ./install.sh --uninstall  lo quita (conserva /etc/ssh-sentinel)
#
#  No activa nada por sí solo: al final te dice qué comandos ejecutar.
#  --root DIR instala dentro de DIR (para pruebas o para crear paquetes).
# =============================================================================
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL=C
umask 022

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=""
ACTION=install

die() { printf 'Error: %s\n' "$1" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall) ACTION=uninstall; shift ;;
        --root)      [[ -n "${2:-}" && -d "$2" ]] || die "--root necesita un directorio existente"
                     ROOT=$(cd -- "$2" && pwd); shift 2 ;;
        -h|--help)   sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)           die "opción desconocida: $1" ;;
    esac
done

[[ -n "$ROOT" || $EUID -eq 0 ]] || die "ejecútalo con sudo: sudo ./install.sh"

BIN="$ROOT/usr/local/bin/ssh-sentinel"
UNITS="$ROOT/etc/systemd/system"
ETC="$ROOT/etc/ssh-sentinel"
UNIT_FILES=(ssh-sentinel.service ssh-sentinel-report.service ssh-sentinel-report.timer)

# Solo se usa systemctl en una instalación real con systemd funcionando
use_systemctl() { [[ -z "$ROOT" && -d /run/systemd/system ]] && command -v systemctl >/dev/null; }

if [[ "$ACTION" == uninstall ]]; then
    if use_systemctl; then
        systemctl disable --now ssh-sentinel.service ssh-sentinel-report.timer 2>/dev/null || true
    fi
    rm -f -- "$BIN"
    for u in "${UNIT_FILES[@]}"; do rm -f -- "$UNITS/$u"; done
    use_systemctl && systemctl daemon-reload
    printf 'ssh-sentinel desinstalado. Se conserva la configuración en %s\n' "$ETC"
    printf 'Para borrarla también: sudo rm -r %s /var/lib/ssh-sentinel\n' "$ETC"
    exit 0
fi

# --- Comprobaciones previas ------------------------------------------------------
for f in ssh-sentinel.sh "${UNIT_FILES[@]/#/systemd/}" config/ssh-sentinel.conf.example; do
    [[ -f "$HERE/$f" ]] || die "falta $f: ejecuta el instalador desde la carpeta del proyecto"
done
bash -n "$HERE/ssh-sentinel.sh" || die "ssh-sentinel.sh tiene errores de sintaxis"
for c in awk sort journalctl; do
    command -v "$c" >/dev/null || printf 'Aviso: no se encontró %s\n' "$c" >&2
done

# --- Programa: root:root 755 (nadie más puede modificarlo, porque se ejecuta como root)
install -d -m 755 "$ROOT/usr/local/bin" "$UNITS"
install -m 755 "$HERE/ssh-sentinel.sh" "$BIN"
[[ -n "$ROOT" ]] || chown root:root "$BIN"

# --- Servicios systemd
for u in "${UNIT_FILES[@]}"; do install -m 644 "$HERE/systemd/$u" "$UNITS/$u"; done

# --- Configuración: nunca se sobrescribe la que ya existe
install -d -m 755 "$ETC"
if [[ -e "$ETC/ssh-sentinel.conf" ]]; then
    printf 'Se conserva tu configuración: %s\n' "$ETC/ssh-sentinel.conf"
else
    install -m 644 "$HERE/config/ssh-sentinel.conf.example" "$ETC/ssh-sentinel.conf"
fi
install -m 600 "$HERE/config/telegram.conf.example" "$ETC/telegram.conf.example"

use_systemctl && systemctl daemon-reload

cat <<EOF

ssh-sentinel $("$BIN" --version | cut -d' ' -f2) instalado:
  Programa:       $BIN
  Configuración:  $ETC/ssh-sentinel.conf
  Servicios:      $UNITS/ssh-sentinel.service (en vivo)
                  $UNITS/ssh-sentinel-report.timer (informe diario 07:00)

Siguientes pasos:
  1. Revisa la configuración:      sudo nano $ETC/ssh-sentinel.conf
  2. Pruébalo:                     sudo ssh-sentinel --since "24 hours ago"
  3. Vigilancia 24 h:              sudo systemctl enable --now ssh-sentinel
  4. Informe diario:               sudo systemctl enable --now ssh-sentinel-report.timer
  5. Ver alertas en vivo:          journalctl -u ssh-sentinel -f
EOF
