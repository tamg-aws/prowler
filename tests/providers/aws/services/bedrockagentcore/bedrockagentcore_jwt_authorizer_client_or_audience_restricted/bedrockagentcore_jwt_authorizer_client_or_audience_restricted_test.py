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

# AgentCore calls this module's mocks do not set up. The service constructor runs
# every collector, and an unstubbed call would surface as a scan error and add a
# spurious region-level MANUAL finding, so they return empty explicitly.
_UNSTUBBED_RESPONSES = {
    "ListMemories": {"memories": []},
    "ListGateways": {"items": []},
    "ListGatewayTargets": {"items": []},
    "ListAgentRuntimes": {"agentRuntimes": []},
    "ListBrowsers": {"browserSummaries": []},
    "ListCodeInterpreters": {"codeInterpreterSummaries": []},
    "GetTokenVault": {"tokenVaultId": "default"},
}


def _unstubbed(operation_name):
    """Return an empty response for an AgentCore call a mock does not stub."""
    return _UNSTUBBED_RESPONSES.get(operation_name)


RES_ID = "test-resource-id"
RES_NAME = "test-resource"
RES_ARN = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
    f":runtime/{RES_ID}"
)
GW_ID = "test-gateway-id"
GW_NAME = "test-gateway"
GW_ARN = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
    f":gateway/{GW_ID}"
)
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
    unstubbed = _unstubbed(operation_name)
    if unstubbed is not None:
        return unstubbed
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
            "authorizerConfiguration": {
                "customJWTAuthorizer": {"discoveryUrl": DISCOVERY_URL}
            },
        }
    unstubbed = _unstubbed(operation_name)
    if unstubbed is not None:
        return unstubbed
    return make_api_call(self, operation_name, kwarg)


def _mock_runtime_unreadable(self, operation_name, kwarg):
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
    unstubbed = _unstubbed(operation_name)
    if unstubbed is not None:
        return unstubbed
    return make_api_call(self, operation_name, kwarg)


def _gateway_mock(authorizer_type):
    """Build a _make_api_call replacement returning one gateway with GetGateway denied.

    authorizerType is a required member of the ListGateways summary, so the
    gateway's scope survives a denied GetGateway.
    """

    def _mock(self, operation_name, kwarg):
        """Mock returning one gateway with given authorizer type, denying GetGateway."""
        if operation_name == "ListGateways":
            return {
                "items": [
                    {
                        "gatewayId": GW_ID,
                        "name": GW_NAME,
                        "authorizerType": authorizer_type,
                    }
                ]
            }
        if operation_name == "GetGateway":
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                operation_name,
            )
        if operation_name == "ListAgentRuntimes":
            return {"agentRuntimes": []}
        unstubbed = _unstubbed(operation_name)
        if unstubbed is not None:
            return unstubbed
        return make_api_call(self, operation_name, kwarg)

    return _mock


_mock_gateway_unreadable = _gateway_mock("CUSTOM_JWT")
_mock_gateway_unreadable_aws_iam = _gateway_mock("AWS_IAM")


def _gateway_detail_mock(authorizer_type="CUSTOM_JWT", jwt_authorizer=None):
    """Build a _make_api_call replacement returning one gateway whose GetGateway succeeds.

    No runtimes are listed, so every finding comes from the gateway loop.
    """

    def _mock(self, operation_name, kwarg):
        """Mock returning one gateway with GetGateway enrichment including JWT authorizer config."""
        if operation_name == "ListGateways":
            return {
                "items": [
                    {
                        "gatewayId": GW_ID,
                        "name": GW_NAME,
                        "authorizerType": authorizer_type,
                    }
                ]
            }
        if operation_name == "GetGateway":
            response = {
                "gatewayId": GW_ID,
                "name": GW_NAME,
                "authorizerType": authorizer_type,
            }
            if jwt_authorizer is not None:
                response["authorizerConfiguration"] = {
                    "customJWTAuthorizer": jwt_authorizer
                }
            return response
        if operation_name == "ListGatewayTargets":
            return {"items": []}
        if operation_name == "ListAgentRuntimes":
            return {"agentRuntimes": []}
        unstubbed = _unstubbed(operation_name)
        if unstubbed is not None:
            return unstubbed
        return make_api_call(self, operation_name, kwarg)

    return _mock


_mock_gateway_allowed_clients = _gateway_detail_mock(
    jwt_authorizer={"discoveryUrl": DISCOVERY_URL, "allowedClients": ["client-1"]}
)
_mock_gateway_allowed_audience = _gateway_detail_mock(
    jwt_authorizer={"discoveryUrl": DISCOVERY_URL, "allowedAudience": ["aud-1"]}
)
_mock_gateway_unrestricted = _gateway_detail_mock(
    jwt_authorizer={"discoveryUrl": DISCOVERY_URL}
)
_mock_gateway_readable_aws_iam = _gateway_detail_mock(authorizer_type="AWS_IAM")


def _mock_empty(self, operation_name, kwarg):
    """No runtime resources at all."""
    if operation_name == "ListAgentRuntimes":
        return {"agentRuntimes": []}
    unstubbed = _unstubbed(operation_name)
    if unstubbed is not None:
        return unstubbed
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
    unstubbed = _unstubbed(operation_name)
    if unstubbed is not None:
        return unstubbed
    return make_api_call(self, operation_name, kwarg)


class Test_bedrockagentcore_jwt_authorizer_client_or_audience_restricted:
    """Unit tests for the bedrockagentcore_jwt_authorizer_client_or_audience_restricted check."""

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
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_jwt_authorizer_client_or_audience_restricted.bedrockagentcore_jwt_authorizer_client_or_audience_restricted.bedrockagentcore_client",
                new=BedrockAgentCore(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_jwt_authorizer_client_or_audience_restricted.bedrockagentcore_jwt_authorizer_client_or_audience_restricted import (
                bedrockagentcore_jwt_authorizer_client_or_audience_restricted,
            )

            return (
                bedrockagentcore_jwt_authorizer_client_or_audience_restricted().execute()
            )

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
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        """A ValidationException from the region must not raise; it yields no findings."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_runtime_unreadable
    )
    @mock_aws
    def test_runtime_detail_unreadable_is_manual_not_skipped(self):
        """ListAgentRuntimes carries no authorizer field, so a denied Get cannot prove out-of-scope."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_gateway_unreadable
    )
    @mock_aws
    def test_gateway_detail_unreadable_is_manual_not_fail(self):
        """A CUSTOM_JWT gateway with a denied GetGateway has unknown, not absent, restrictions."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert result[0].resource_id == GW_ID
        assert result[0].resource_arn == GW_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_gateway_unreadable_aws_iam,
    )
    @mock_aws
    def test_gateway_not_custom_jwt_stays_out_of_scope(self):
        """The summary's authorizerType keeps an AWS_IAM gateway out of scope without GetGateway."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_gateway_allowed_clients
    )
    @mock_aws
    def test_gateway_allowed_clients_passes(self):
        """A gateway restricting allowedClients accepts only tokens minted for it."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "restricts allowed clients or audience" in result[0].status_extended
        assert GW_NAME in result[0].status_extended
        assert result[0].resource_id == GW_ID
        assert result[0].resource_arn == GW_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_gateway_allowed_audience
    )
    @mock_aws
    def test_gateway_allowed_audience_only_passes(self):
        """allowedAudience alone is a sufficient restriction; either one satisfies the control."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "restricts allowed clients or audience" in result[0].status_extended
        assert result[0].resource_id == GW_ID
        assert result[0].resource_arn == GW_ARN

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_gateway_unrestricted
    )
    @mock_aws
    def test_gateway_unrestricted_fails(self):
        """A readable CUSTOM_JWT gateway with neither restriction accepts any issuer token."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no allowed clients or audience restriction" in result[0].status_extended
        assert GW_NAME in result[0].status_extended
        assert result[0].resource_id == GW_ID
        assert result[0].resource_arn == GW_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_gateway_readable_aws_iam
    )
    @mock_aws
    def test_readable_gateway_not_custom_jwt_is_skipped(self):
        """An AWS_IAM gateway is out of scope even when GetGateway succeeds."""
        assert self._run() == []
