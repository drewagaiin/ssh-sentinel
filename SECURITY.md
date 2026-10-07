# Política de seguridad

Si encuentras una vulnerabilidad en ssh-sentinel (por ejemplo, una forma de que un registro manipulado ejecute comandos, o de filtrar el token de Telegram), no abras un issue público: usa **"Report a vulnerability"** en la pestaña *Security* de este repositorio. Incluye la versión (`./ssh-sentinel.sh --version`), los pasos para reproducirlo y el impacto. Respuesta en un máximo de 7 días.

## Garantías de diseño

1. **No bloquea nada por sí solo**: solo sugiere comandos y genera scripts para revisar.
2. **Sin red** salvo que se pida `--telegram`.
3. **Entrada no confiable**: el contenido de los registros nunca se ejecuta. La IP se toma de la parte fija de la línea (no del nombre de usuario, que elige el atacante) y se valida antes de escribirla en un script. Los caracteres de control y bytes raros se sustituyen.
4. **Registros falsificados**: en el journal solo se aceptan mensajes de sshd escritos por root (`_UID=0`, un campo que pone el propio journal).
5. **Secretos protegidos**: el token de Telegram exige permisos 600 y nunca aparece en la línea de comandos.
6. **Configuración protegida**: `/etc/ssh-sentinel/ssh-sentinel.conf` se lee como texto (nunca con `source`), debe ser de root y no modificable por otros (con `IGNORE` se podrían ocultar ataques), y cada valor se valida igual que en la línea de comandos.
7. **Servicio con mínimo privilegio**: se ejecuta sin ninguna capacidad de root, sin poder escribir en el sistema ni ver `/home`, con filtro de llamadas al sistema y límite de memoria (exposición 1.7 en `systemd-analyze security`).
8. **Falla de forma segura**: si un registro no se puede leer, termina con error en lugar de decir "sin alertas".

## Cómo se revisó la versión 1.1.0

- Revisión adversarial independiente en tres rondas: cada hallazgo se reprodujo, se corrigió y se añadió como prueba.
- Ataques reales contra un OpenSSH 9.6 con rsyslog, incluido el engaño de la IP en el nombre de usuario.
- ShellCheck 0.9, 0.10 y 0.11 sin avisos; 53 pruebas en Kali, Debian 12 y Ubuntu 22.04/24.04.
