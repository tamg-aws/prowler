"""Tests that an unanswered field is reported rather than read as a verdict.

Every case here is a response that arrived successfully but did not carry the
value the check needs. Reading such a field as its falsy default turns "the API
did not tell us" into a definite PASS or FAIL, which is the failure mode these
tests exist to prevent.
"""

from unittest import mock


import botocore


from moto import mock_aws


from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


GW_ID = "test-gateway-id"


GW_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/{GW_ID}"


BROWSER_ID = "test-browser-id"


BROWSER_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:browser/{BROWSER_ID}"


MEMORY_ID = "test-memory-id"


MEMORY_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:memory/{MEMORY_ID}"


EMPTY = {
    "ListMemories": {"memories": []},
    "ListGateways": {"items": []},
    "ListGatewayTargets": {"items": []},
    "ListAgentRuntimes": {"agentRuntimes": []},
    "ListBrowsers": {"browserSummaries": []},
    "ListCodeInterpreters": {"codeInterpreterSummaries": []},
    "GetTokenVault": {
        "tokenVaultId": "default",
        "kmsConfiguration": {"keyType": "CustomerManagedKey"},
    },
}


def _build(stub):
    """Instantiate BedrockAgentCore under the given _make_api_call stub."""
    from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import BedrockAgentCore

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch("botocore.client.BaseClient._make_api_call", new=stub),
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
    ):
        return BedrockAgentCore(aws_provider)


def _run(check_name, service):
    """Execute a check against the given service instance."""
    with mock.patch(
        f"prowler.providers.aws.services.bedrockagentcore.{check_name}.{check_name}.bedrockagentcore_client",
        new=service,
    ):
        module = __import__(
            f"prowler.providers.aws.services.bedrockagentcore.{check_name}.{check_name}",
            fromlist=[check_name],
        )
        return getattr(module, check_name)().execute()


def _browser_recording_without_enabled(self, operation_name, kwarg):
    """The browser reports a recording destination but no enabled flag."""
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {
                    "browserId": BROWSER_ID,
                    "browserArn": BROWSER_ARN,
                    "name": "browser",
                    "status": "READY",
                }
            ]
        }
    if operation_name == "GetBrowser":
        return {
            "browserId": BROWSER_ID,
            "name": "browser",
            "browserArn": BROWSER_ARN,
            "networkConfiguration": {"networkMode": "VPC"},
            "recording": {"s3Location": {"bucket": "b", "prefix": "p"}},
        }
    if operation_name in EMPTY:
        return EMPTY[operation_name]
    return make_api_call(self, operation_name, kwarg)


def _browser_without_recording(self, operation_name, kwarg):
    """The browser reports no recording block at all."""
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {
                    "browserId": BROWSER_ID,
                    "browserArn": BROWSER_ARN,
                    "name": "browser",
                    "status": "READY",
                }
            ]
        }
    if operation_name == "GetBrowser":
        return {
            "browserId": BROWSER_ID,
            "name": "browser",
            "browserArn": BROWSER_ARN,
            "networkConfiguration": {"networkMode": "VPC"},
        }
    if operation_name in EMPTY:
        return EMPTY[operation_name]
    return make_api_call(self, operation_name, kwarg)


class Test_browser_recording_enabled_tri_state:
    """An omitted enabled flag is unknown; an absent block is off."""

    @mock_aws
    def test_recording_without_enabled_is_manual(self):
        """enabled is optional with no documented default, so it is unknown."""
        service = _build(_browser_recording_without_enabled)

        assert service.browsers[BROWSER_ARN].recording_enabled is None

        results = _run("bedrockagentcore_browser_session_recording_enabled", service)
        assert len(results) == 1
        assert results[0].status == "MANUAL"
        assert results[0].status_extended.endswith(".")

    @mock_aws
    def test_no_recording_block_is_fail(self):
        """No recording configuration at all is a definite "not recording"."""
        service = _build(_browser_without_recording)

        assert service.browsers[BROWSER_ARN].recording_enabled is False

        results = _run("bedrockagentcore_browser_session_recording_enabled", service)
        assert len(results) == 1
        assert results[0].status == "FAIL"
