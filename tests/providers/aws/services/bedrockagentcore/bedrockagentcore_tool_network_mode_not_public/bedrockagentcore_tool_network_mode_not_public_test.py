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

# AgentCore listings this module's mocks do not set up. The service constructor
# calls every collector, and an unstubbed call would surface as a scan error and
# add a spurious region-level MANUAL finding, so they return empty explicitly.
_EMPTY_LISTINGS = {
    "ListMemories": {"memories": []},
    "ListGateways": {"items": []},
    "ListGatewayTargets": {"items": []},
    "ListAgentRuntimes": {"agentRuntimes": []},
    "ListBrowsers": {"browserSummaries": []},
    "ListCodeInterpreters": {"codeInterpreterSummaries": []},
}


def _default_agentcore(operation_name):
    """Return an empty listing for an AgentCore call a mock does not stub."""
    return _EMPTY_LISTINGS.get(operation_name)


RES_ID = "test-resource-id"
RES_NAME = "test-resource"
RES_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:code-interpreter/test-resource-id"
BROWSER_ID = "test-browser-id"
BROWSER_NAME = "test-browser"
BROWSER_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:browser/{BROWSER_ID}"
KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"
DISCOVERY_URL = (
    "https://example.auth.us-east-1.amazoncognito.com/.well-known/openid-configuration"
)


def _mock_pass(self, operation_name, kwarg):
    """One compliant code-interpreter in us-east-1."""
    if operation_name == "ListCodeInterpreters":
        return {
            "codeInterpreterSummaries": [
                {
                    "codeInterpreterArn": RES_ARN,
                    "codeInterpreterId": RES_ID,
                    "name": RES_NAME,
                }
            ]
        }
    if operation_name == "GetCodeInterpreter":
        return {
            "codeInterpreterId": RES_ID,
            "name": RES_NAME,
            "codeInterpreterArn": RES_ARN,
            "networkConfiguration": {"networkMode": "SANDBOX"},
        }
    default = _default_agentcore(operation_name)
    if default is not None:
        return default
    return make_api_call(self, operation_name, kwarg)


def _mock_fail(self, operation_name, kwarg):
    """One non-compliant code-interpreter in us-east-1."""
    if operation_name == "ListCodeInterpreters":
        return {
            "codeInterpreterSummaries": [
                {
                    "codeInterpreterArn": RES_ARN,
                    "codeInterpreterId": RES_ID,
                    "name": RES_NAME,
                }
            ]
        }
    if operation_name == "GetCodeInterpreter":
        return {
            "codeInterpreterId": RES_ID,
            "name": RES_NAME,
            "codeInterpreterArn": RES_ARN,
            "networkConfiguration": {"networkMode": "PUBLIC"},
        }
    default = _default_agentcore(operation_name)
    if default is not None:
        return default
    return make_api_call(self, operation_name, kwarg)


def _mock_unreadable_code_interpreter(self, operation_name, kwarg):
    """The code interpreter is listed, but GetCodeInterpreter is denied."""
    if operation_name == "ListCodeInterpreters":
        return {
            "codeInterpreterSummaries": [
                {
                    "codeInterpreterArn": RES_ARN,
                    "codeInterpreterId": RES_ID,
                    "name": RES_NAME,
                }
            ]
        }
    if operation_name == "GetCodeInterpreter":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    default = _default_agentcore(operation_name)
    if default is not None:
        return default
    return make_api_call(self, operation_name, kwarg)


def _mock_browser_pass(self, operation_name, kwarg):
    """One compliant browser in us-east-1, and no code interpreters."""
    if operation_name == "ListCodeInterpreters":
        return {"codeInterpreterSummaries": []}
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {
                    "browserArn": BROWSER_ARN,
                    "browserId": BROWSER_ID,
                    "name": BROWSER_NAME,
                }
            ]
        }
    if operation_name == "GetBrowser":
        return {
            "browserId": BROWSER_ID,
            "name": BROWSER_NAME,
            "browserArn": BROWSER_ARN,
            # BrowserNetworkConfiguration accepts only PUBLIC and VPC -- SANDBOX
            # is code-interpreter-only, so it cannot stand in for the pass case.
            "networkConfiguration": {"networkMode": "VPC"},
        }
    default = _default_agentcore(operation_name)
    if default is not None:
        return default
    return make_api_call(self, operation_name, kwarg)


def _mock_browser_fail(self, operation_name, kwarg):
    """One non-compliant browser in us-east-1, and no code interpreters."""
    if operation_name == "ListCodeInterpreters":
        return {"codeInterpreterSummaries": []}
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {
                    "browserArn": BROWSER_ARN,
                    "browserId": BROWSER_ID,
                    "name": BROWSER_NAME,
                }
            ]
        }
    if operation_name == "GetBrowser":
        return {
            "browserId": BROWSER_ID,
            "name": BROWSER_NAME,
            "browserArn": BROWSER_ARN,
            "networkConfiguration": {"networkMode": "PUBLIC"},
        }
    default = _default_agentcore(operation_name)
    if default is not None:
        return default
    return make_api_call(self, operation_name, kwarg)


def _mock_unreadable_browser(self, operation_name, kwarg):
    """The browser is listed, but GetBrowser is denied; the browser loop is separate."""
    if operation_name == "ListCodeInterpreters":
        return {"codeInterpreterSummaries": []}
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {
                    "browserArn": BROWSER_ARN,
                    "browserId": BROWSER_ID,
                    "name": BROWSER_NAME,
                }
            ]
        }
    if operation_name == "GetBrowser":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    default = _default_agentcore(operation_name)
    if default is not None:
        return default
    return make_api_call(self, operation_name, kwarg)


def _mock_empty(self, operation_name, kwarg):
    """No code-interpreter resources at all."""
    if operation_name == "ListCodeInterpreters":
        return {"codeInterpreterSummaries": []}
    default = _default_agentcore(operation_name)
    if default is not None:
        return default
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """The API is not available in the audited region."""
    if operation_name == "ListCodeInterpreters":
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Bedrock AgentCore is not supported in this region.",
                }
            },
            operation_name,
        )
    default = _default_agentcore(operation_name)
    if default is not None:
        return default
    return make_api_call(self, operation_name, kwarg)


class Test_bedrockagentcore_tool_network_mode_not_public:
    """Unit tests for the bedrockagentcore_tool_network_mode_not_public check.

    The check walks code interpreters and browsers in two separate loops, so each
    one is asserted on its own PASS, FAIL and MANUAL path rather than assuming the
    loops behave alike."""

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
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_tool_network_mode_not_public.bedrockagentcore_tool_network_mode_not_public.bedrockagentcore_client",
                new=BedrockAgentCore(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_tool_network_mode_not_public.bedrockagentcore_tool_network_mode_not_public import (
                bedrockagentcore_tool_network_mode_not_public,
            )

            return bedrockagentcore_tool_network_mode_not_public().execute()

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
        "botocore.client.BaseClient._make_api_call",
        new=_mock_unreadable_code_interpreter,
    )
    @mock_aws
    def test_code_interpreter_detail_unreadable_is_manual_not_pass(self):
        """A failed GetCodeInterpreter must not be reported as compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_browser_pass)
    @mock_aws
    def test_browser_compliant(self):
        """A compliant browser yields exactly one PASS."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == BROWSER_ID
        assert result[0].resource_arn == BROWSER_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert AWS_REGION_US_EAST_1 in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_browser_fail)
    @mock_aws
    def test_browser_non_compliant(self):
        """A browser on PUBLIC network mode yields exactly one FAIL."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == BROWSER_ID
        assert result[0].resource_arn == BROWSER_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unreadable_browser
    )
    @mock_aws
    def test_browser_detail_unreadable_is_manual_not_pass(self):
        """The browser loop gates on detail_retrieved too, not just the code interpreter one."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert result[0].resource_id == BROWSER_ID
        assert result[0].resource_arn == BROWSER_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
