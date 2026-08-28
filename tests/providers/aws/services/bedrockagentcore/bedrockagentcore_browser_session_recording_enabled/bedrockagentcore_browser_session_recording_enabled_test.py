from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

RES_ID = "test-resource-id"
RES_NAME = "test-resource"
RES_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:browser/test-resource-id"
KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"
DISCOVERY_URL = (
    "https://example.auth.us-east-1.amazoncognito.com/.well-known/openid-configuration"
)


def _mock_pass(self, operation_name, kwarg):
    """One compliant browser in us-east-1."""
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {"browserArn": RES_ARN, "browserId": RES_ID, "name": RES_NAME}
            ]
        }
    if operation_name == "GetBrowser":
        return {
            "browserId": RES_ID,
            "name": RES_NAME,
            "browserArn": RES_ARN,
            "recording": {
                "enabled": True,
                "s3Location": {"bucket": "b", "prefix": "p"},
            },
        }
    return make_api_call(self, operation_name, kwarg)


def _mock_recording_flag_absent(self, operation_name, kwarg):
    """A browser with a recording block that omits the optional `enabled` member.

    `enabled` has no documented default, so reading its absence as false would FAIL a
    browser that may in fact be recording. The check reports MANUAL instead.
    """
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {"browserArn": RES_ARN, "browserId": RES_ID, "name": RES_NAME}
            ]
        }
    if operation_name == "GetBrowser":
        return {
            "browserId": RES_ID,
            "name": RES_NAME,
            "browserArn": RES_ARN,
            "recording": {"s3Location": {"bucket": "b", "prefix": "p"}},
        }
    return make_api_call(self, operation_name, kwarg)


def _mock_fail(self, operation_name, kwarg):
    """One non-compliant browser in us-east-1."""
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {"browserArn": RES_ARN, "browserId": RES_ID, "name": RES_NAME}
            ]
        }
    if operation_name == "GetBrowser":
        return {
            "browserId": RES_ID,
            "name": RES_NAME,
            "browserArn": RES_ARN,
            "recording": {"enabled": False},
        }
    return make_api_call(self, operation_name, kwarg)


def _mock_unreadable(self, operation_name, kwarg):
    """The browser is listed, but GetBrowser is denied."""
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {"browserArn": RES_ARN, "browserId": RES_ID, "name": RES_NAME}
            ]
        }
    if operation_name == "GetBrowser":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_empty(self, operation_name, kwarg):
    """No browser resources at all."""
    if operation_name == "ListBrowsers":
        return {"browserSummaries": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """The API is not available in the audited region."""
    if operation_name == "ListBrowsers":
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Bedrock AgentCore is not supported in this region.",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


class Test_bedrockagentcore_browser_session_recording_enabled:
    """Unit tests for the bedrockagentcore_browser_session_recording_enabled check."""

    def _run(self):
        """Import the service + check under the active mocks and execute."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_browser_session_recording_enabled.bedrockagentcore_browser_session_recording_enabled.bedrockagentcore_client",
                new=BedrockAgentCore(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_browser_session_recording_enabled.bedrockagentcore_browser_session_recording_enabled import (
                bedrockagentcore_browser_session_recording_enabled,
            )

            return bedrockagentcore_browser_session_recording_enabled().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        """No resources means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_pass)
    @mock_aws
    def test_compliant(self):
        """A compliant resource yields exactly one PASS."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert AWS_REGION_US_EAST_1 in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_fail)
    @mock_aws
    def test_non_compliant(self):
        """A non-compliant resource yields exactly one FAIL."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_recording_flag_absent
    )
    @mock_aws
    def test_recording_configured_without_enabled_flag_is_manual(self):
        """A recording block with no `enabled` member is MANUAL, not PASS and not FAIL.

        Covers the third MANUAL branch. A MANUAL -> PASS mutation on it survived before
        this test existed, so the branch was reachable in production and unasserted here.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            "does not report whether recording is enabled" in result[0].status_extended
        )
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        """A ValidationException from the region must not raise; it yields no findings."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_unreadable)
    @mock_aws
    def test_detail_unreadable_is_manual_not_fail(self):
        """A failed GetBrowser must not be reported as recording-disabled."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
