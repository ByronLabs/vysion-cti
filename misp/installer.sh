# Script for using on systems installed with the official MISP installer

MISP_HOME="/var/www/MISP"
MISP_MODULES_HOME="/usr/local/src/misp-modules"

MISP_VENV="$MISP_HOME/venv"
MISP_OBJECTS_PATH="$MISP_HOME/app/files/misp-objects/objects"
EXPANSION_MODULES_PATH="$MISP_MODULES_HOME/misp_modules/modules/expansion"

cp modules/expansion/* "$EXPANSION_MODULES_PATH/"
chown -R misp "$EXPANSION_MODULES_PATH/"

# find . -type d -exec chmod o+x {}
# find . -type f -exec chmod o+r {}

source "$MISP_VENV/bin/activate"
pip install -r modules/requirements.txt
pip install $MISP_MODULES_HOME

sed -e 's#ExecStart=/var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s#ExecStart=/var/www/MISP/venv/bin/misp-modules -l 127.0.0.1#g' /etc/systemd/system/misp-modules.service

cp -r objects/* "$MISP_OBJECTS_PATH/" && cp -r objects/* "$MISP_HOME/PyMISP/pymisp/data/misp-objects/objects/" 

chown -R www-data:www-data "$MISP_HOME/"

systemctl daemon-reload
systemctl restart misp-modules
