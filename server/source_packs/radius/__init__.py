"""RADIUS/NPS accounting pipeline of the RADIUS source pack.

Parses NPS accounting records, resolves session identities, registers the
collected evidence in PostgreSQL and builds the VPN session read models.
The NPS Event Log normalizer stays in ``server/source_packs/windows_nps_radius.py``.
"""
