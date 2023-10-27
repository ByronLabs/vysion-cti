# Vysion MISP

It's very easy to install Vysion MISP! Just need to have already installed [MISP Core and MISP Modules](https://www.misp-project.org/download/) and follow the instructions write below.

> Python 3.7 or higher version required.
> An installer "installer.sh" is available to install the "Objects" and "Expansion Module" parts in this same directory.

# Organisation

1. Administration > Add Organisations

- Organisation Identifier: `Byron Labs`
- UUID: `efcd64f5-49db-49d6-a7cb-07c23d12e534`
- Logo: `organization/logo.png`
- Nationality: Spain
- Sector: infosec

# Objects

Move the objects (i.e., `vysion-page` and `vysion-ransomware-feed`) to all folders that use `misp-objects` (usually `$MISP/app/files/misp-objects/objects` and `$PYMISP/app/files/misp-objects/objects`). Reinstall all secondary packages that have been modified (e.g., reinstall PyMISP so that the objects created are passed to the `virtualenv` packages)

# Expansion Module

1. Install dependencies (`requirements.txt`) in the environment used by the MISP instance (e.g., virtualenv, poetry, or system).
2. Insert file `modules/extension/vysion-expansion.py` in `$MISP_MODULES/modules/expansion/`
3. Restart (if applicable) the `misp-modules` service being used
4. Enable module in Administration > Server Settings & Maintenance > Plugin settings > Enrichment: `vysion-expansion_enabled = true`
5. Enter api key in the configuration menu: `vysion-expansion_apikey`

# Feeds

1. Open the menu to add feeds: Sync Actions > List feeds > Add feed

- Enabled: `true`
- Name: `Vysion Ransomware Feed`
- Provider: `Byron Labs`
- Input Source: `Network`
- URL: `https://api.vysion.ai/api/v1/feed/ransomware/misp`
- Source Format: `MISP Feed`
- Headers
    - `x-api-key: ************`
- Distribution: `Your organization only`

2. Once installed click on `Fetch and store all feed metadata`
