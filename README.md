# Vysion-CTI


Vysion integrations for threat intelligence platforms.

## Integrations

### MISP

The [`misp/`](misp/) directory contains enrichment modules and feed tooling for
MISP, including searches for ransomware groups and victims.

### OpenCTI

The [`opencti/`](opencti/) directory contains three connectors:

- **Observable enrichment:** document mentions, messaging profile associations
  and optional leak metadata, represented as cited evidence notes. Captures of
  the same page are grouped without automatically declaring it malicious.
- **Ransomware feed:** hourly imports of the previous 24 hours, including victims,
  threat actors, incidents, countries and sectors where available.
- **Wallet detection feed:** an independently enabled feed of cryptocurrency
  wallets and associated evidence notes.

See the [OpenCTI installation and configuration guide](opencti/README.md) for
Docker Compose setup, supported observables, source permissions and tests.

You can request a demo or an API key on our [website](https://byronlabs.io).

## References

- https://github.com/MISP/misp-modules
- https://developers.vysion.ai

## MISP examples

![img1](https://github.com/ByronLabs/vysion-cti/assets/38075180/c52c8591-5b5e-4bd3-946a-9f124feaebb8)


![img2](https://github.com/ByronLabs/vysion-cti/assets/38075180/d50d92bc-7717-4b6e-8978-98b21fac1367)


![img3](https://github.com/ByronLabs/vysion-cti/assets/38075180/9fcaab6d-9f6d-4e97-b3d9-b678378e071a)
