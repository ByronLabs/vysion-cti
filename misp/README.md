# Vysion MISP

> Necesario python3.7

# Organización

1. Administration > Add Organisations

- Organisation Identifier: `Byron Labs`
- UUID: `efcd64f5-49db-49d6-a7cb-07c23d12e534`
- Logo: `organization/logo.png`
- Nationality: Spain
- Sector: infosec

# Objetos

Mover los objetos (i.e., `vysion-page` y `vysion-ransomware-feed`) a todas las carpetas que utilicen `misp-objects` (normalmente `$MISP/app/files/misp-objects/objects` y `$PYMISP/app/files/misp-objects/objects`). Reinstalar todos los paquetes secundarios que hayan sido modificados (e.g., volver a instalar PyMISP para que los objetos creados pasen a los paquetes del `virtualenv`)

# Módulo de expansión

1. Instalar dependencias (`requirements.txt`) en el entorno utilizado por la instancia de MISP (e.g., virtualenv, poetry, o sistema).
2. Introducir fichero `modules/extension/vysion-expansion.py` en `$MISP_MODULES/modules/expansion/`
3. Reiniciar (si procede) el servicio de `misp-modules` que se esté utilizando
4. Habilitar módulo en Administration > Server Settings & Maintenance > Plugin settings  > Enrichment: `vysion-expansion_enabled = true`
5. Introducir api key en el menú de configuración: `vysion-expansion_apikey`

# Feeds


1. Abrir al menú para añadir feeds: Sync Actions > List feeds > Add feed

- Enabled: `true`
- Name: `Vysion Ransomware Feed`
- Provider: `Byron Labs`
- Input Source: `Network`
- URL: `https://api.vysion.ai/api/v1/feed/ransomware/misp`
- Source Format: `MISP Feed`
- Headers
    - `x-api-key: ************`
- Distribution: `Your organization only`

2. Una vez instalado pulsar en `Fetch and store all feed metadata`