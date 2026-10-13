"""The threat lab runner (levels 1–2 in gVisor, level 4 in Firecracker) — a
separate deployable, not plugin code (proposal §03.5, D28). See
``integrations/threat-lab/README.md``.

Modules: ``api`` (loopback job API) → ``runner`` (one job) → ``sandbox``
(gVisor containers) running ``probe`` (inside the sandbox; ``rules`` for
level 2), or ``microvm`` (Firecracker microVMs, level 4; ``kvm`` guards it)
running ``guest`` (inside the microVM, with ``bait``) and recording traffic
read by ``traffic``; ``watch`` holds both sandboxes to their deadline and the
egress caps → ``output`` (the raw output the curator's Evidence Extractor reads;
the lab never builds Evidence) and ``artifacts`` (raw files, 90-day retention).
``schema`` is the by-path load of the plugin's evidence contract (its note
vocabulary and key/digest rules).

Nothing is imported here: the probe runs inside the sandbox image, where the
plugin's schema file does not exist.
"""
