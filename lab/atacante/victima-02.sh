cd ~
echo "== ftp con ~/.netrc"
python3 - <<'EOF'
import ftplib, netrc
host = next(iter(netrc.netrc().hosts))
login, _, password = netrc.netrc().authenticators(host)
try:
    with ftplib.FTP(host, timeout=5) as f:
        f.login(login, password)
except ftplib.all_errors as e:
    print("ftp", e)
EOF
echo "== redis con REDIS_URL de ~/.env"
# `redis-cli -u` rompe el parser de OpenCanary ("invalid bulk length") y no deja la clave
# en el log: se prueba también con -a, que sí la registra.
URL="$(grep '^REDIS_URL=' .env | cut -d= -f2-)"
redis-cli -u "$URL" ping 2>&1 | head -1
PW="$(printf '%s' "$URL" | sed -E 's#^redis://:([^@]*)@.*#\1#')"
HOST="$(printf '%s' "$URL" | sed -E 's#^.*@([^:/]*):.*#\1#')"
redis-cli --no-auth-warning -h "$HOST" -a "$PW" ping 2>&1 | head -1
