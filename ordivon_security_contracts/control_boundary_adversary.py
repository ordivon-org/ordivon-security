"""Compatibility import for the moved control-boundary evaluation.

Active adversarial evaluations live in :mod:`ordivon_security_evaluations`.
The frozen Campaign contract package retains this import only so committed
reports and older callers remain reproducible.
"""

from ordivon_security_evaluations.control_boundary import *  # noqa: F401,F403
