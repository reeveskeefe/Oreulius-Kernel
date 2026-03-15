# Firmware Policy

Oreulia does not commit GPU firmware blobs into the repository.

Firmware-backed devices may expose:

- probe support
- capability reporting
- explicit activation failure when firmware is unavailable

Firmware loading is handled through external hooks and validation paths.

