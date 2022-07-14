# Vysion MISP

> Necesario python3.7

## Expansion

1. Instalar dependencias (`requirements.txt`)
2. Instalar `modules/extension/vysion-expansion.py` en `$MISP_MODULES/modules/expansion/`
3. Administration > Server Settings & Maintenance > Plugin settings  > Enrichment > 

## Objetos

1. Mover los objetos a la carpeta `$MISP/app/files/misp-objects/objects`
2. 

# Categories and types

https://www.circl.lu/doc/misp/categories-and-types/

- Expansion
- Objects (https://www.misp-project.org/2021/03/17/MISP-Objects-101.html/)

## Auto

Dev:

```
tar cvfz misp.tar.gz * && scp -P 2222 -i ~/.ssh/deviandel misp.tar.gz localhost:/tmp && rm misp.tar.gz
junquera@deviandel:~/Documentos/projects/vysion-cti/misp$ 
```

Server:

```
mkdir -p /tmp/misp && cd /tmp/misp && rm -rf * && tar xvfz ../misp.tar.gz && bash installer.sh
```

OJO

El script de instalación de MISP lanza misp-modules con el flag `-s` (sólo módulos "oficiales" del pip). Hay que desactivarlo para que funcione este paquete