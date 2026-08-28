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


def _memory_summary_without_arn(self, operation_name, kwarg):
    """A memory summary carrying an id but no arn."""
    if operation_name == "ListMemories":
        return {"memories": [{"id": MEMORY_ID}]}
    if operation_name == "GetMemory":
        return {
            "memory": {
                "id": MEMORY_ID,
                "name": "memory",
                "encryptionKeyArn": f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/k",
            }
        }
    if operation_name in EMPTY:
        return EMPTY[operation_name]
    return make_api_call(self, operation_name, kwarg)


class Test_memory_without_an_arn_is_still_discovered:
    """Both arn and id are optional on the MemorySummary, unlike its siblings."""

    @mock_aws
    def test_arn_is_derived_from_the_id(self):
        """A memory reported without an ARN must not be dropped from the scan."""
        service = _build(_memory_summary_without_arn)

        assert MEMORY_ARN in service.memories
        assert service.memories[MEMORY_ARN].id == MEMORY_ID

        results = _run("bedrockagentcore_memory_encrypted_with_cmk", service)
        assert len(results) == 1
        assert results[0].status == "PASS"
