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
    from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
        BedrockAgentCore,
    )

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


def _gateway_without_get_authorizer(self, operation_name, kwarg):
    """ListGateways reports the authorizer type; GetGateway omits it."""
    if operation_name == "ListGateways":
        return {
            "items": [
                {
                    "gatewayId": GW_ID,
                    "name": "gw",
                    "gatewayArn": GW_ARN,
                    "status": "READY",
                    "authorizerType": "CUSTOM_JWT",
                }
            ]
        }
    if operation_name == "GetGateway":
        return {"gatewayId": GW_ID, "name": "gw", "gatewayArn": GW_ARN}
    if operation_name in EMPTY:
        return EMPTY[operation_name]
    return make_api_call(self, operation_name, kwarg)


class Test_gateway_authorizer_type_is_not_discarded:
    """GetGateway must not erase what ListGateways already established."""

    @mock_aws
    def test_summary_authorizer_type_survives_a_get_without_one(self):
        """authorizerType is required on the summary, so it is known good.

        Overwriting it with an absent GetGateway value would turn a known
        CUSTOM_JWT gateway into an unknown one, and this check skips gateways
        whose authorizer type is not CUSTOM_JWT -- so the gateway would silently
        drop out of the results entirely.
        """
        service = _build(_gateway_without_get_authorizer)

        assert service.gateways[GW_ARN].authorizer_type == "CUSTOM_JWT"

        results = _run(
            "bedrockagentcore_jwt_authorizer_client_or_audience_restricted", service
        )
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].resource_id == GW_ID
