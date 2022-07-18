# Script for using on systems installed with the official MISP installer

MISP_HOME="/var/www/MISP"
MISP_MODULES_HOME="/usr/local/src/misp-modules"

MISP_VENV="$MISP_HOME/venv"
MISP_OBJECTS_PATH="$MISP_HOME/app/files/misp-objects/objects"
EXPANSION_MODULES_PATH="$MISP_MODULES_HOME/misp_modules/modules/expansion"

WEB_USER="www-data"
MISP_USER="misp"

# Create objects
OBJECT_PATHS=("$MISP_OBJECTS_PATH/" "$MISP_HOME/PyMISP/pymisp/data/misp-objects/objects/")
for OPATH in ${OBJECT_PATHS[*]}; do
    cp -r objects/* "$OPATH";
    chown -R $WEB_USER:$WEB_USER "$OPATH";
done
# Reinstall PyMISP (so it reinstalls the objects)
"$MISP_VENV/bin/python3" -m pip install $MISP_HOME/PyMISP

# Install expansion modules
cp modules/expansion/* "$EXPANSION_MODULES_PATH/"
chown -R $MISP_USER "$EXPANSION_MODULES_PATH/"

# Install dependencies
"$MISP_VENV/bin/python3" -m pip install -r modules/requirements.txt
"$MISP_VENV/bin/python3" -m pip install $MISP_MODULES_HOME
chown -R $WEB_USER:$WEB_USER "$MISP_HOME/"

# Enable custom modules in misp-modules service
sed -i -e 's#ExecStart=/var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s#ExecStart=/var/www/MISP/venv/bin/misp-modules -l 127.0.0.1#g' /etc/systemd/system/misp-modules.service
systemctl daemon-reload
systemctl restart misp-modules

# TODO Use MISP OpenAPI to configure the last steps
