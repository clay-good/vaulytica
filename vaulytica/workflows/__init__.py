"""Automated workflows for common security use cases."""

from vaulytica.workflows.external_pii_alert import (
    ExternalPIIAlertWorkflow,
    ExternalPIIAlertConfig,
    ExternalPIIAlertResult,
)
from vaulytica.workflows.gmail_external_pii_alert import (
    GmailExternalPIIAlertWorkflow,
    GmailExternalPIIAlertConfig,
    GmailExternalPIIAlertResult,
)

__all__ = [
    "ExternalPIIAlertWorkflow",
    "ExternalPIIAlertConfig",
    "ExternalPIIAlertResult",
    "GmailExternalPIIAlertWorkflow",
    "GmailExternalPIIAlertConfig",
    "GmailExternalPIIAlertResult",
]

