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
RES_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:memory/test-resource-id"
KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"
DISCOVERY_URL = (
    "https://example.auth.us-east-1.amazoncognito.com/.well-known/openid-configuration"
)


def _mock_pass(self, operation_name, kwarg):
    """One compliant memory in us-east-1."""
    if operation_name == "ListMemories":
        return {"memories": [{"arn": RES_ARN, "id": RES_ID, "name": RES_NAME}]}
    if operation_name == "GetMemory":
        return {
            "memory": {
                "id": RES_ID,
                "name": RES_NAME,
                "arn": RES_ARN,
                "encryptionKeyArn": KMS_KEY_ARN,
            }
        }
    return make_api_call(self, operation_name, kwarg)


def _mock_fail(self, operation_name, kwarg):
    """One non-compliant memory in us-east-1."""
    if operation_name == "ListMemories":
        return {"memories": [{"arn": RES_ARN, "id": RES_ID, "name": RES_NAME}]}
    if operation_name == "GetMemory":
        return {"memory": {"id": RES_ID, "name": RES_NAME, "arn": RES_ARN}}
    return make_api_call(self, operation_name, kwarg)


def _mock_unreadable(self, operation_name, kwarg):
    """The memory is listed, but GetMemory is denied."""
    if operation_name == "ListMemories":
        return {"memories": [{"arn": RES_ARN, "id": RES_ID, "name": RES_NAME}]}
    if operation_name == "GetMemory":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_empty(self, operation_name, kwarg):
    """No memory resources at all."""
    if operation_name == "ListMemories":
        return {"memories": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """The API is not available in the audited region."""
    if operation_name == "ListMemories":
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


class Test_bedrockagentcore_memory_encrypted_with_cmk:
    """Unit tests for the bedrockagentcore_memory_encrypted_with_cmk check."""

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
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_memory_encrypted_with_cmk.bedrockagentcore_memory_encrypted_with_cmk.bedrockagentcore_client",
                new=BedrockAgentCore(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_memory_encrypted_with_cmk.bedrockagentcore_memory_encrypted_with_cmk import (
                bedrockagentcore_memory_encrypted_with_cmk,
            )

            return bedrockagentcore_memory_encrypted_with_cmk().execute()

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

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_unreadable)
    @mock_aws
    def test_detail_unreadable_is_manual_not_fail(self):
        """A failed GetMemory must not be reported as unencrypted."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        # GetMemory is the only source of the name, so the id carries the message.
        assert RES_ID in result[0].status_extended
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
