cd ~
echo "== mysql con ~/.my.cnf"
mysql --skip-ssl -e 'select 1' 2>&1 | head -1
echo "== intranet con ~/.env"
python3 - <<'EOF'
import urllib.parse, urllib.request
env = dict(l.split("=", 1) for l in open(".env").read().splitlines() if "=" in l)
datos = urllib.parse.urlencode({"username": env["INTRANET_USER"], "password": env["INTRANET_PASSWORD"]}).encode()
r = urllib.request.urlopen(urllib.request.Request(env["INTRANET_URL"] + "index.html", data=datos), timeout=5)
print("http", r.status)
EOF
