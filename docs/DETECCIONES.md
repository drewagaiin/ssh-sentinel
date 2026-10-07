# Detecciones

Cómo decide `ssh-sentinel` cada alerta. Los umbrales se pueden ajustar con las opciones indicadas.

## Qué cuenta como "intento fallido"

| Línea de OpenSSH | ¿Cuenta? | Por qué |
|------------------|----------|---------|
| `Failed password for root from IP` | ✅ Sí | Contraseña incorrecta |
| `Failed keyboard-interactive/pam for …` | ✅ Sí | Contraseña incorrecta por PAM |
| `Invalid user admin from IP port P` | ✅ Sí (una vez) | Usuario inexistente |
| `Failed password for invalid user admin from IP port P` | ➖ No, si ya se contó su `Invalid user` | Es el mismo intento; se unen por IP + puerto |
| `message repeated 4 times: [ Failed password … ]` | ✅ Sí, 4 veces | rsyslog comprime líneas idénticas |
| `Failed publickey for …` | ❌ No | Normal: el cliente prueba varias llaves |
| `message repeated 999999 times: [ … ]` | ⚠️ Como mucho 100 | Una sesión real no repite tanto; evita que una línea falsa cuelgue el análisis |
| Cualquier línea que no sea de `sshd`, `sshd-session` o `sshd-auth` | ❌ No | Otro programa |
| `sshd[…]` en medio de la línea de otro programa | ❌ No | El nombre del programa debe estar en su posición |

### La IP se toma del final de la línea

El nombre de usuario lo elige el atacante y OpenSSH lo guarda **tal cual, con espacios**. Con el usuario `x from 8.8.8.8 port 22`, la línea real queda así:

```
Failed password for invalid user x from 8.8.8.8 port 22 from 127.0.0.1 port 40474 ssh2
```

Quien lea el primer `from` cree que el atacante es 8.8.8.8 y puede acabar bloqueando una IP inocente (un DNS, la puerta de enlace de la empresa). `ssh-sentinel` toma la IP de la **cola fija** que escribe sshd (`from IP port N ssh2`) y la valida. Probado contra un OpenSSH 9.6 real ([tests/fixtures/real-inyeccion.log](../tests/fixtures/real-inyeccion.log)).

## Alertas

### Accesos exitosos: solo cuentan las últimas 24 horas

Para decidir si un acceso es sospechoso se miran los fallos de las **24 horas anteriores**. Un usuario que se equivoca una vez al día durante una semana no es un ataque; 30 fallos en una hora seguidos de un acceso, sí.

| Situación (últimas 24 h, umbral `--after-fail` = 5) | Alerta |
|------|--------|
| La IP falló 5+ veces **contra esa misma cuenta** y luego entró | `SSH-COMPROMISE` (crítica) |
| La IP probó 5+ usuarios distintos (spraying) y luego entró con uno | `SSH-COMPROMISE` (crítica) |
| La IP falló 5+ veces contra **otras** cuentas y entró con una distinta | `SSH-SUSPECT-LOGIN` (alta) |
| Entra con contraseña a una cuenta que recibió 5+ fallos desde **otras** IPs | `SSH-SUSPECT-LOGIN` (alta) |

### SSH-COMPROMISE · Crítica · MITRE T1078, T1110
Contraseña adivinada: acceso exitoso justo después de muchos fallos de esa IP (ver la tabla). Respuesta: cambiar la contraseña de la cuenta, revisar qué hizo (`last`, `journalctl _UID=…`) y tratarlo como incidente. La IP se incluye en los bloqueos sugeridos.

### SSH-SUSPECT-LOGIN · Alta · MITRE T1078, T1110
El patrón de una **botnet**: una IP adivina la contraseña y entra **otra** que nunca falló, o entra alguien desde una IP que estaba atacando otras cuentas. Puede ser legítimo (una oficina detrás de una sola IP), por eso es alta y no crítica, y **no** se sugiere bloquear esa IP: hay que confirmar con el dueño de la cuenta.

### SSH-DISTRIBUTED · Media · MITRE T1110
**20 o más IPs distintas** atacan el mismo usuario (`--distributed`). Cada IP hace pocos intentos para no superar los umbrales por IP. Bloquear IP por IP no sirve: la respuesta es desactivar las contraseñas o limitar SSH a tus redes.

### SSH-BRUTE · Alta · MITRE T1110.001
Una IP alcanza **10 fallos dentro de 10 minutos** (`--threshold`, `--window`). Se calcula con una **ventana deslizante**: se mira el peor intervalo de 10 minutos, no el total del día. Así no se confunde a un usuario que se equivoca unas pocas veces al día con un ataque.

### SSH-SPRAY · Alta · MITRE T1110.003
Una IP prueba **5 o más usuarios distintos** (`--spray`). El *password spraying* prueba pocas contraseñas comunes contra muchos usuarios, a menudo **despacio** para no superar los umbrales de fuerza bruta ni bloquear cuentas. Por eso se detecta por cantidad de usuarios, no por velocidad.

### SSH-ROOT · Alta (contraseña) / Media (llave) · MITRE T1078.003
Inicio de sesión directo como `root`. Aunque sea legítimo, impide saber qué persona hizo cada cosa. Mejor: entrar con usuario propio y usar `sudo`.

### SSH-PASSWORD · Baja · MITRE T1110
Accesos con contraseña en lugar de llave. No es un ataque, pero indica que el servidor acepta contraseñas, que pueden adivinarse o filtrarse.

## Modo en vivo (`--follow`)

Usa la misma lógica, pero avisa en el momento exacto en que se cruza el umbral (por ejemplo, en el décimo intento). Para no saturar, la fuerza bruta de una misma IP se avisa como mucho una vez por ventana, el spraying una vez por IP y el ataque distribuido una vez al día por usuario.

Pensado para funcionar meses como servicio:
- **Memoria acotada**: cada hora olvida las IPs sin actividad en 24 h, y la cola de fallos recientes tiene un tope (400.000). Con 2 millones de intentos al día usa menos de 400 MB.
- **Telegram**: como mucho `--telegram-rate` mensajes por minuto (10); las alertas **críticas se envían siempre**. Lo que se omite se cuenta y se avisa en el siguiente mensaje.

## Limitaciones

- El formato syslog clásico (`Oct  5 03:00:01`) no incluye el año: se asume el actual, o el anterior si la fecha quedaría en el futuro (enero leyendo diciembre).
- Las horas se muestran tal como aparecen en el registro, sin convertir zonas horarias.
- En `/var/log/auth.log` (rsyslog), un usuario local puede escribir líneas falsas con `logger -t sshd`. En el journal no: solo se aceptan mensajes de root. Por eso, si hay journal, se usa el journal.
- Si el servidor solo acepta llaves (`PasswordAuthentication no`), los bots que prueban usuarios reales no dejan líneas `Failed password`: solo se verán los usuarios inexistentes. Es el mejor escenario: no hay contraseña que adivinar.
