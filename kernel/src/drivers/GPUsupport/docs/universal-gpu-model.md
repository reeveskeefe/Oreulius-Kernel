# Oreulius Universal GPU Model

Oreulius treats every GPU as a graph of:

- apertures
- engines
- queues
- fences
- present targets

Unknown hardware is never driven by guessed command streams. It is only
promoted to a tier the kernel can actually prove from standardized interfaces
or explicit plugin support.

