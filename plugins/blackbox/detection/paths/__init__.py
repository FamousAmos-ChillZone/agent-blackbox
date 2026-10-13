"""Which paths an action touches, and which of them the operator protects.

* :mod:`.shell_files` — the paths a shell command reads, copies or packs up.
* :mod:`.protected` — the user's protected-path rule (``detect_custom_fileaccess``).
* :mod:`.keychain` — the macOS keychain, a built-in Trader Shield rule (``detect_keychain_access``).

Used through :mod:`plugins.blackbox.detection` by the rest of the plugin.
"""
