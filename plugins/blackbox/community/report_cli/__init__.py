"""The reporter's command line: `blackbox report` and its verbs.

A ``community`` sub-package (the community folder reached its file alarm):

* :mod:`.report_command` — the parser, filing a report, ``--status``.
* :mod:`.statement_verbs` — disputes and retractions, and the shared send-and-record step.
* :mod:`.report_rights` — export with key backup, key restore, identity erasure.
"""

from .report_command import add_report_parser, cmd_report, print_community_status

__all__ = ["add_report_parser", "cmd_report", "print_community_status"]
