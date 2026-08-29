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
RES_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/test-resource-id"
KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"
DISCOVERY_URL = (
    "https://example.auth.us-east-1.amazoncognito.com/.well-known/openid-configuration"
)


def _mock_pass(self, operation_name, kwarg):
    """One compliant runtime in us-east-1."""
    if operation_name == "ListAgentRuntimes":
        return {
            "agentRuntimes": [
                {
                    "agentRuntimeArn": RES_ARN,
                    "agentRuntimeId": RES_ID,
                    "agentRuntimeName": RES_NAME,
                }
            ]
        }
    if operation_name == "GetAgentRuntime":
        return {
            "agentRuntimeId": RES_ID,
            "agentRuntimeName": RES_NAME,
            "agentRuntimeArn": RES_ARN,
            "authorizerConfiguration": {
                "customJWTAuthorizer": {
                    "discoveryUrl": DISCOVERY_URL,
                    "allowedClients": ["client-1"],
                }
            },
        }
    return make_api_call(self, operation_name, kwarg)


def _mock_fail(self, operation_name, kwarg):
    """One non-compliant runtime in us-east-1."""
    if operation_name == "ListAgentRuntimes":
        return {
            "agentRuntimes": [
                {
                    "agentRuntimeArn": RES_ARN,
                    "agentRuntimeId": RES_ID,
                    "agentRuntimeName": RES_NAME,
                }
            ]
        }
    if operation_name == "GetAgentRuntime":
        return {
            "agentRuntimeId": RES_ID,
            "agentRuntimeName": RES_NAME,
            "agentRuntimeArn": RES_ARN,
        }
    return make_api_call(self, operation_name, kwarg)


def _mock_unreadable(self, operation_name, kwarg):
    """The runtime is listed, but GetAgentRuntime is denied."""
    if operation_name == "ListAgentRuntimes":
        return {
            "agentRuntimes": [
                {
                    "agentRuntimeArn": RES_ARN,
                    "agentRuntimeId": RES_ID,
                    "agentRuntimeName": RES_NAME,
                }
            ]
        }
    if operation_name == "GetAgentRuntime":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_empty(self, operation_name, kwarg):
    """No runtime resources at all."""
    if operation_name == "ListAgentRuntimes":
        return {"agentRuntimes": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """The API is not available in the audited region."""
    if operation_name == "ListAgentRuntimes":
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


class Test_bedrockagentcore_runtime_inbound_authorizer_configured:
    """Unit tests for the bedrockagentcore_runtime_inbound_authorizer_configured check."""

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
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_inbound_authorizer_configured.bedrockagentcore_runtime_inbound_authorizer_configured.bedrockagentcore_client",
                new=BedrockAgentCore(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_inbound_authorizer_configured.bedrockagentcore_runtime_inbound_authorizer_configured import (
                bedrockagentcore_runtime_inbound_authorizer_configured,
            )

            return bedrockagentcore_runtime_inbound_authorizer_configured().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        """No resources means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_pass)
    @mock_aws
    def test_compliant(self):
        """A compliant resource yields exactly one PASS, with the full message pinned."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].status_extended == (
            f"Bedrock AgentCore agent runtime {RES_NAME} has an inbound authorizer configuration "
            f"in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_fail)
    @mock_aws
    def test_non_compliant(self):
        """A non-compliant resource yields exactly one FAIL, with the full message pinned.

        The message is asserted in full rather than by substring because a wording change has no
        predicate to flip, so nothing else can catch one. It must say the runtime falls back to IAM
        SigV4 and carries no validated end-user identity -- NOT that it is unauthenticated, which is
        what an earlier wording implied and which AWS documentation contradicts.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].status_extended == (
            f"Bedrock AgentCore agent runtime {RES_NAME} has no inbound authorizer configuration "
            f"in region {AWS_REGION_US_EAST_1}, so inbound calls fall back to IAM SigV4 and carry "
            f"no validated end-user identity."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_fail)
    @mock_aws
    def test_fail_does_not_claim_the_runtime_is_unauthenticated(self):
        """The FAIL must not assert an unauthenticated endpoint.

        A positive full-string assertion pins the new text; only this negative one stops the wider
        claim returning if someone later shortens the message. SigV4 authenticates the calling AWS
        principal, so "unauthenticated" and "no authorizer" without the fallback named are both
        wider than the check establishes.
        """
        message = self._run()[0].status_extended
        assert "unauthenticated" not in message
        assert "has no inbound authorizer configured" not in message
        assert "IAM SigV4" in message

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
        """A failed GetAgentRuntime must not be reported as unauthenticated."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
