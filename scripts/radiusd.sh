#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Environnement : tout doit pointer dans $SNAP (en snap strict, /usr = hote)
# ---------------------------------------------------------------------------
ARCH_TRIPLET="$(uname -m)-linux-gnu"
export PATH="$SNAP/usr/sbin:$SNAP/usr/bin:$SNAP/sbin:$SNAP/bin:$PATH"
export LD_LIBRARY_PATH="$SNAP/usr/lib/freeradius:$SNAP/usr/lib/$ARCH_TRIPLET:$SNAP/lib/$ARCH_TRIPLET${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="$SNAP/etc/ssl/openssl.cnf"

DICTDIR="$SNAP/usr/share/freeradius"
RADDB_SRC="$SNAP/etc/freeradius/3.0"
RADDB="$SNAP_DATA/raddb"
CONF="$RADDB/radiusd.conf"

# ---------------------------------------------------------------------------
# Premier demarrage : copie de la config de reference + corrections de chemins
# ---------------------------------------------------------------------------
if [ ! -f "$RADDB/.initialized" ]; then
    echo "Premier demarrage : initialisation de $RADDB"
    rm -rf "$RADDB"
    mkdir -p "$RADDB"
    cp -a "$RADDB_SRC/." "$RADDB/"

    # Chemins : on utilise $ENV{...} (resolu par FreeRADIUS a la lecture) pour
    # ne PAS figer le numero de revision du snap dans le fichier.
    sed -i -E \
        -e 's|^(\s*)prefix\s*=.*|\1prefix = $ENV{SNAP}/usr|' \
        -e 's|^(\s*)exec_prefix\s*=.*|\1exec_prefix = $ENV{SNAP}/usr|' \
        -e 's|^(\s*)localstatedir\s*=.*|\1localstatedir = $ENV{SNAP_DATA}/var|' \
        -e 's|^(\s*)logdir\s*=.*|\1logdir = $ENV{SNAP_DATA}/var/log/freeradius|' \
        -e 's|^(\s*)raddbdir\s*=.*|\1raddbdir = $ENV{SNAP_DATA}/raddb|' \
        -e 's|^(\s*)libdir\s*=.*|\1libdir = $ENV{SNAP}/usr/lib/freeradius|' \
        -e 's|^(\s*)(user\|group)\s*=\s*freerad|\1#\2 = freerad|' \
        "$CONF"

    # Le module EAP Debian utilise le certificat "snakeoil" du systeme
    # (/etc/ssl/private/ssl-cert-snakeoil.key), absent dans le snap : on le
    # redirige vers les certificats generes plus bas par "make all".
    sed -i -E \
        -e 's|^(\s*private_key_file\s*=).*|\1 ${certdir}/server.pem|' \
        -e 's|^(\s*certificate_file\s*=).*|\1 ${certdir}/server.pem|' \
        -e 's|^(\s*ca_file\s*=).*|\1 ${cadir}/ca.pem|' \
        "$RADDB/mods-available/eap"

    # Les liens mods-enabled / sites-enabled sont crees par le postinst Debian,
    # qui n'est PAS execute par snapcraft : on les cree ici.
    for m in always attr_filter chap date detail digest eap exec expiration expr files \
             linelog logintime mschap pap preprocess radutmp realm unix unpack utf8; do
        [ -e "$RADDB/mods-available/$m" ] && ln -sf "../mods-available/$m" "$RADDB/mods-enabled/$m"
    done
    for s in default inner-tunnel; do
        ln -sf "../sites-available/$s" "$RADDB/sites-enabled/$s"
    done

    # Pas d'ecoute IPv6 : le demarrage echoue si IPv6 est absent du noyau
    # (802.1X + switch = IPv4 suffisant).
    awk '
      /^listen \{/ { buf=$0; inblk=1; v6=0; next }
      inblk { buf = buf "\n" $0; if ($0 ~ /^[ \t]*ipv6addr/) v6=1
              if ($0 ~ /^\}/) { if (!v6) print buf; inblk=0 }
              next }
      { print }' "$RADDB/sites-available/default" > "$RADDB/sites-available/default.new"
    mv "$RADDB/sites-available/default.new" "$RADDB/sites-available/default"

    # Client local (utilise par le bouton "Test" de la web UI)
    LOCAL_SECRET="$(openssl rand -hex 24)"
    printf '%s' "$LOCAL_SECRET" > "$SNAP_DATA/local-secret"
    chmod 600 "$SNAP_DATA/local-secret"
    # FreeRADIUS refuse deux clients avec la meme IP : le clients.conf Debian
    # declare deja "localhost" (127.0.0.1 / ::1) avec le secret "testing123".
    # On remplace ce secret connu par un secret aleatoire.
    sed -i "s|secret\s*=\s*testing123|secret = $LOCAL_SECRET|" "$RADDB/clients.conf"
    touch "$RADDB/.initialized"
fi

mkdir -p "$SNAP_DATA/var/log/freeradius/radacct" "$SNAP_DATA/var/run/freeradius"

# ---------------------------------------------------------------------------
# Certificats EAP (PEAP/EAP-TTLS), generes une seule fois
# ---------------------------------------------------------------------------
if [ ! -f "$RADDB/certs/server.pem" ]; then
    echo "Generation des certificats EAP (premiere fois seulement)..."
    # Par defaut les certificats de test expirent au bout de 60 jours !
    sed -i -E 's/^(default_days\s*=\s*).*/\13650/' "$RADDB"/certs/{ca,server,client,inner-server}.cnf
    ( cd "$RADDB/certs" && make all )
fi

exec "$SNAP/usr/sbin/freeradius" -f -d "$RADDB" -D "$DICTDIR" "$@"
