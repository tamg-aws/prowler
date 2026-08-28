"""Tests that an unreadable inventory is reported rather than passed over.

Findings are emitted per resource, so a Region whose listing failed contributes
none and would be indistinguishable from a Region that holds none. Each check
must therefore emit a region-level MANUAL naming the API error, and must stay
silent for a Region the service does not serve.
"""

from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_NAME = "bedrockagentcore_runtime_inbound_authorizer_configured"
STORES = [("agent_runtimes_scan_errors", "runtime/unknown")]


class _StubClient:
    """Minimal stand-in exposing only what the region-level branch reads."""

    def __init__(self, errors):
        """Initialize a stub client with scan errors for AgentCore runtimes."""
        self.audited_account = AWS_ACCOUNT_NUMBER
        self.audited_partition = "aws"
        self.agent_runtimes = {}
        self.agent_runtimes_scan_errors = {}
        for store in errors:
            setattr(self, store, {AWS_REGION_US_EAST_1: "AccessDeniedException"})


def _run(errors):
    """Execute the check against a stub whose named stores hold an error."""
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            f"prowler.providers.aws.services.bedrockagentcore.{CHECK_NAME}.{CHECK_NAME}.bedrockagentcore_client",
            new=_StubClient(errors),
        ),
    ):
        module = __import__(
            f"prowler.providers.aws.services.bedrockagentcore.{CHECK_NAME}.{CHECK_NAME}",
            fromlist=[CHECK_NAME],
        )
        return getattr(module, CHECK_NAME)().execute()


class Test_bedrockagentcore_runtime_inbound_authorizer_configured_unreadable_inventory:
    """Tests for the region-level MANUAL findings of bedrockagentcore_runtime_inbound_authorizer_configured."""

    @mock_aws
    def test_denied_listing_reports_manual_not_silence(self):
        """Every unreadable listing this check reads yields a MANUAL finding."""
        results = _run([store for store, _ in STORES])

        assert len(results) == len(STORES)
        assert {report.status for report in results} == {"MANUAL"}
        placeholders = {report.resource_id for report in results}
        assert placeholders == {placeholder for _, placeholder in STORES}
        for report in results:
            assert report.region == AWS_REGION_US_EAST_1
            assert "could not be listed" in report.status_extended
            assert "AccessDeniedException" in report.status_extended
            assert report.status_extended.endswith(".")
            assert report.resource_arn == (
                f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:"
                f"{AWS_ACCOUNT_NUMBER}:{report.resource_id}"
            )

    @mock_aws
    def test_no_error_no_findings(self):
        """A fully-listed but empty account yields nothing, not a spurious MANUAL."""
        assert _run([]) == []

    @mock_aws
    def test_each_store_is_read_independently(self):
        """A failure in one listing is reported without inventing the others."""
        for store, placeholder in STORES:
            results = _run([store])
            assert len(results) == 1, store
            assert results[0].status == "MANUAL"
            assert results[0].resource_id == placeholder
