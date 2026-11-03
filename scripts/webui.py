#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web UI du snap FreeRADIUS pour ctrlX OS.

Sert sur un socket UNIX ; le reverse proxy du portail ctrlX (443)
y forwarde /freeradius, donc l'UI hérite de l'authentification ctrlX.
"""

import html
import os
import re
import socket
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SNAP = os.environ.get("SNAP", "")
SNAP_DATA = os.environ.get("SNAP_DATA", os.path.join(os.getcwd(), "dev-data"))
SNAP_NAME = "ctrlx-freeradius"

RADDB = os.path.join(SNAP_DATA, "raddb")
USERS_FILE = os.path.join(RADDB, "mods-config", "files", "authorize")
CLIENTS_FILE = os.path.join(RADDB, "clients.conf")
LOCAL_SECRET_FILE = os.path.join(SNAP_DATA, "local-secret")
CA_FILE = os.path.join(RADDB, "certs", "ca.pem")

SOCK_DIR = os.path.join(SNAP_DATA, "package-run", SNAP_NAME)
SOCK_FILE = os.path.join(SOCK_DIR, "web.sock")

MARK_BEGIN = "# >>> MANAGED-USERS >>>"
MARK_END = "# <<< MANAGED-USERS <<<"
MAX_USERS = 10


# ------------------------------------------------------------------ users

def read_users():
    users = []
    if not os.path.exists(USERS_FILE):
        return users
    with open(USERS_FILE, encoding="utf-8") as f:
        text = f.read()
    m = re.search(re.escape(MARK_BEGIN) + r"\n(.*?)" + re.escape(MARK_END), text, re.S)
    if not m:
        return users
    for chunk in m.group(1).split("\n\n"):
        lines = [l.strip("\t ") for l in chunk.strip().splitlines() if l.strip()]
        if not lines:
            continue
        um = re.match(r'([A-Za-z0-9._@-]+)\s+Cleartext-Password\s*:=\s*"(.*)"', lines[0])
        if not um:
            continue
        user = {"name": um.group(1), "password": um.group(2), "vlan": ""}
        for extra in lines[1:]:
            vm = re.search(r'Tunnel-Private-Group-ID\s*=\s*"?([0-9]+)"?', extra)
            if vm:
                user["vlan"] = vm.group(1)
        users.append(user)
    return users


def _users_block(users):
    entries = []
    for u in users:
        line = '%s\tCleartext-Password := "%s"' % (u["name"], u["password"])
        if u.get("vlan"):
            line += ("\n\tTunnel-Type = 13,\n\tTunnel-Medium-Type = 6,\n"
                     '\tTunnel-Private-Group-ID = "%s"' % u["vlan"])
        entries.append(line)
    return MARK_BEGIN + "\n" + "\n\n".join(entries) + "\n" + MARK_END + "\n"


def write_users(users):
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, encoding="utf-8") as f:
            text = f.read()
    else:
        text = "# FreeRADIUS users file\n"
    if MARK_BEGIN in text and MARK_END in text:
        head, _, rest = text.partition(MARK_BEGIN)
        _, _, tail = rest.partition(MARK_END)
        tail = tail.lstrip("\n")
    else:
        head, tail = "", text
    new = _users_block(users) + "\n\n" + head + tail
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new)
    os.replace(tmp, USERS_FILE)
    os.chmod(USERS_FILE, 0o600)


# ---------------------------------------------------------------- actions

def restart_radius():
    try:
        r = subprocess.run(["snapctl", "restart", "ctrlx-freeradius.freeradius"],
                           capture_output=True, text=True, timeout=30)
        return (r.returncode == 0,
                "FreeRADIUS redémarré." if r.returncode == 0
                else "Échec du redémarrage : " + (r.stdout + r.stderr).strip())
    except Exception as e:  # noqa: BLE001
        return False, "Échec du redémarrage : %s" % e


def test_user(name, password):
    """Teste un couple utilisateur / mot de passe (PAP) contre le FreeRADIUS local."""
    # Un saut de ligne dans un champ permettrait d'injecter d'autres attributs
    # dans la requête envoyée à radclient.
    for value in (name, password):
        if any(ord(c) < 32 for c in value):
            return False, "Caractères de contrôle interdits."
    if not name:
        return False, "Nom d'utilisateur vide."

    try:
        with open(LOCAL_SECRET_FILE, encoding="utf-8") as f:
            secret = f.read().strip()
    except OSError:
        return False, "Secret local introuvable (le service freeradius a-t-il démarré ?)."
    if not secret:
        return False, "Secret local vide."

    # radtest a /usr codé en dur : on appelle radclient directement.
    trip = os.uname().machine + "-linux-gnu"
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = ":".join([
        os.path.join(SNAP, "usr", "lib", "freeradius"),
        os.path.join(SNAP, "usr", "lib", trip),
        os.path.join(SNAP, "lib", trip),
    ])

    def esc(s):
        return s.replace("\\", "\\\\").replace('"', '\\"')

    request = 'User-Name = "%s"\nUser-Password = "%s"\n' % (esc(name), esc(password))
    cmd = [
        os.path.join(SNAP, "usr", "bin", "radclient"),
        "-D", os.path.join(SNAP, "usr", "share", "freeradius"),
        "-t", "3", "-r", "1",          # 3 s de timeout, 1 seule tentative
        "127.0.0.1:1812", "auth", secret,
    ]
    try:
        r = subprocess.run(cmd, input=request, capture_output=True, text=True,
                           env=env, timeout=15)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        return ("Received Access-Accept" in out), out[-1500:]
    except Exception as e:  # noqa: BLE001
        return False, str(e)


# ------------------------------------------------------------------- page
STYLE = ("body{font-family:sans-serif;margin:2em;color:#222}"
         "h1{font-size:1.3em}h2{font-size:1.05em;margin-top:1.6em}"
         "table{border-collapse:collapse;margin:.5em 0}"
         "td,th{border:1px solid #ccc;padding:.35em .6em;text-align:left}"
         "input,textarea,button{font:inherit}"
         "textarea{width:100%;height:16em;font-family:monospace}"
         ".msg{padding:.5em .8em;background:#f2f6fa;border-left:4px solid #005691;margin:1em 0}"
         ".hint{color:#666;font-size:.85em}")


def render_page(message):
    users = read_users()
    try:
        with open(CLIENTS_FILE, encoding="utf-8") as f:
            clients = f.read()
    except OSError:
        clients = ""

    rows = []
    for i, u in enumerate(users):
        rows.append(
            "<tr><td>%s</td><td>&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</td>"
            "<td>%s</td><td>"
            "<form method='post' style='display:inline'>"
            "<input type='hidden' name='action' value='delete'>"
            "<input type='hidden' name='index' value='%d'>"
            "<button>Supprimer</button></form></td></tr>"
            % (html.escape(u["name"]), html.escape(u["vlan"] or "&#8212;"), i))
    rows_html = "".join(rows) or "<tr><td colspan='4'>Aucun utilisateur</td></tr>"

    return """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<title>FreeRADIUS</title><style>%s</style></head><body>
<h1>FreeRADIUS &#8212; gestion des acc&egrave;s 802.1X</h1>
%s
<h2>Utilisateurs (%d / %d)</h2>
<table><tr><th>Nom</th><th>Mot de passe</th><th>VLAN</th><th></th></tr>%s</table>
<form method="post">
  <input type="hidden" name="action" value="add">
  <p><label>Nom <input name="name" required></label>
     <label>Mot de passe <input type="password" name="password" minlength="8" required></label>
     <label>VLAN (optionnel) <input name="vlan" size="5"></label>
     <button>Ajouter</button></p>
  <p class="hint">Le VLAN place le port du switch dans ce VLAN apr&egrave;s authentification
  (Tunnel-Private-Group-ID). Vide = pas de changement.</p>
</form>

<h2>Clients RADIUS (switchs) &#8212; clients.conf</h2>
<form method="post">
  <input type="hidden" name="action" value="save_clients">
  <textarea name="content">%s</textarea>
  <p><button>Enregistrer</button></p>
  <p class="hint">D&eacute;clarez ici le switch : client &lt;nom&gt; { ipaddr = &lt;IP&gt; ;
  secret = &lt;secret long et al&eacute;atoire&gt; }. Une erreur de syntaxe emp&ecirc;che le
  d&eacute;marrage du daemon &#8212; en cas de doute, red&eacute;marrer et v&eacute;rifier le Logbook.</p>
</form>

<h2>Test &amp; maintenance</h2>
<form method="post" style="display:inline">
  <input type="hidden" name="action" value="test">
  <label>Nom <input name="tname"></label>
  <label>Mot de passe <input type="password" name="tpassword"></label>
  <button>Tester (PAP local)</button>
</form>
<form method="post" style="display:inline">
  <input type="hidden" name="action" value="restart">
  <button>Red&eacute;marrer FreeRADIUS</button>
</form>
<p><a href="?action=ca">T&eacute;l&eacute;charger le certificat CA (pour les supplicants PEAP)</a></p>
<p class="hint">Le test PAP valide le fichier users seulement ; le chemin EAP complet
(PEAP/EAP-TLS) se valide depuis le switch avec un poste client.</p>
</body></html>""" % (STYLE,
                     "<div class='msg'>%s</div>" % message if message else "",
                     len(users), MAX_USERS, rows_html,
                     html.escape(clients))


# --------------------------------------------------------------- handler

class Handler(BaseHTTPRequestHandler):
    server_version = "ctrlx-freeradius-ui/1.0"

    def log_message(self, fmt, *args):
        # Sur un socket Unix, client_address est '' : address_string() lève un
        # IndexError et la requête reste sans réponse. On masque aussi la query
        # string (elle peut contenir un jeton).
        msg = re.sub(r"\?\S*", "?...", fmt % args)
        print("web - %s" % msg, flush=True)

    def _send_html(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if qs.get("action", [""])[0] == "ca":
            try:
                with open(CA_FILE, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pem-file")
                self.send_header("Content-Disposition",
                                 "attachment; filename=freeradius-ca.pem")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except OSError:
                self._send_html(b"<h3>CA non trouve (genere au 1er demarrage)</h3>", 404)
            return
        self._send_html(render_page(None).encode("utf-8"))

    def do_POST(self):
        message = ""
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
            action = data.get("action", [""])[0]

            if action == "add":
                name = data.get("name", [""])[0].strip()
                password = data.get("password", [""])[0]
                vlan = data.get("vlan", [""])[0].strip()
                if not re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", name):
                    message = "Nom d'utilisateur invalide."
                elif len(password) < 8:
                    message = "Mot de passe trop court (8 caract&egrave;res minimum)."
                elif any(c in '"\\' or ord(c) < 32 for c in password):
                    # Le mot de passe est écrit entre guillemets dans le fichier
                    # users : un guillemet ou un antislash le corromprait et
                    # empêcherait FreeRADIUS de démarrer.
                    message = ("Caract&egrave;res interdits dans le mot de passe : "
                               "guillemet, antislash et caract&egrave;res de contr&ocirc;le.")
                elif vlan and not re.fullmatch(r"[0-9]{1,4}", vlan):
                    message = "VLAN invalide."
                else:
                    users = [u for u in read_users() if u["name"] != name]
                    if len(users) >= MAX_USERS:
                        message = "Maximum %d utilisateurs atteint." % MAX_USERS
                    else:
                        users.append({"name": name, "password": password, "vlan": vlan})
                        write_users(users)
                        ok, msg = restart_radius()
                        message = "Utilisateur %s enregistr&eacute;. %s" % (
                            html.escape(name), msg)
            elif action == "delete":
                try:
                    i = int(data.get("index", ["-1"])[0])
                    users = read_users()
                    removed = users.pop(i)
                    write_users(users)
                    ok, msg = restart_radius()
                    message = "Utilisateur %s supprim&eacute;. %s" % (
                        html.escape(removed["name"]), msg)
                except (ValueError, IndexError):
                    message = "Index invalide."
            elif action == "save_clients":
                content = data.get("content", [""])[0]
                tmp = CLIENTS_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(content)
                os.replace(tmp, CLIENTS_FILE)
                os.chmod(CLIENTS_FILE, 0o600)
                ok, msg = restart_radius()
                message = "clients.conf enregistr&eacute;. %s" % msg
            elif action == "restart":
                ok, msg = restart_radius()
                message = msg
            elif action == "test":
                ok, out = test_user(data.get("tname", [""])[0].strip(),
                                    data.get("tpassword", [""])[0])
                message = ("<pre style='color:%s'>R&eacute;sultat : %s\n\n%s</pre>"
                           % ("green" if ok else "red",
                              "SUCCES (Access-Accept)" if ok else "ECHEC",
                              html.escape(out)))
            else:
                message = "Action inconnue."
        except Exception as e:  # noqa: BLE001
            message = "Erreur : %s" % html.escape(str(e))
        self._send_html(render_page(message).encode("utf-8"))


class UnixThreadingHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True


def main():
    os.makedirs(SOCK_DIR, exist_ok=True)
    if os.path.exists(SOCK_FILE):
        os.unlink(SOCK_FILE)
    server = UnixThreadingHTTPServer(SOCK_FILE, Handler)
    os.chmod(SOCK_FILE, 0o666)  # le reverse proxy ctrlX doit pouvoir s'y connecter
    print("FreeRADIUS web UI: ecoute sur", SOCK_FILE, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
