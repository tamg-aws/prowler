from unittest import mock

import botocore
import pytest
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
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/test-tool-execution-role"
BROWSER_ID = "test-browser-id"
BROWSER_NAME = "test-browser"
BROWSER_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:browser/test-browser-id"

SCOPED_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::example-bucket/example-prefix/*",
        }
    ],
}
ADMIN_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
SERVICE_WIDE_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
}
# The four actions of the PassRole+AgentCoreCreateInterpreter+InvokeInterpreter escalation
# combination, all in ONE document. check_privilege_escalation requires a combination's actions to
# be a subset of a single document's effective actions, so one document is the only form it can
# detect. Deliberately not service-wide and not Action:*, so it reaches the escalation test rather
# than being caught by check_admin_access or check_full_service_access above it.
ESCALATION_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock-agentcore:CreateCodeInterpreter",
                "bedrock-agentcore:InvokeCodeInterpreter",
                "bedrock-agentcore:StartCodeInterpreterSession",
                "iam:PassRole",
            ],
            "Resource": "*",
        }
    ],
}


def _tool_mock(execution_role_arn=ROLE_ARN):
    """Build a _make_api_call replacement returning one code interpreter."""

    def _mock(self, operation_name, kwarg):
        """Mock returning a code interpreter with the given execution role ARN."""
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
            response = {
                "codeInterpreterId": RES_ID,
                "name": RES_NAME,
                "codeInterpreterArn": RES_ARN,
                "networkConfiguration": {"networkMode": "SANDBOX"},
            }
            if execution_role_arn is not None:
                response["executionRoleArn"] = execution_role_arn
            return response
        default = _default_agentcore(operation_name)
        if default is not None:
            return default
        return make_api_call(self, operation_name, kwarg)

    return _mock


_mock_with_role = _tool_mock()
_mock_without_role = _tool_mock(execution_role_arn=None)


def _browser_mock(self, operation_name, kwarg):
    """One BROWSER with an execution role, and no code interpreters at all.

    The browser arm of the collection was unexercised: deleting it left every test green while a
    browser with an admin execution role went from one FAIL to no findings. A code-interpreter
    fixture cannot cover it, because each tool type is collected separately.
    """
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
            "networkConfiguration": {"networkMode": "SANDBOX"},
            "executionRoleArn": ROLE_ARN,
        }
    default = _default_agentcore(operation_name)
    if default is not None:
        return default
    return make_api_call(self, operation_name, kwarg)


def _mock_unreadable(self, operation_name, kwarg):
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


def _mock_empty(self, operation_name, kwarg):
    """No tool resources at all."""
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


# Distinguishes "the test passed nothing" from "the test passed None on purpose".
_UNSET = object()


class _Role:
    """Minimal stand-in for the IAM service Role model."""

    def __init__(self, attached_policies=None, inline_policies=None):
        """Initialize a role with the given attached and inline policy lists."""
        self.arn = ROLE_ARN
        self.name = ROLE_ARN.rsplit("/", 1)[-1]
        self.attached_policies = attached_policies or []
        self.inline_policies = inline_policies or []


class _Policy:
    """Minimal stand-in for the IAM service Policy model."""

    def __init__(self, document):
        """Initialize a policy with the given IAM policy document."""
        self.document = document


class Test_bedrockagentcore_tool_execution_role_no_wildcard_privileges:
    """Covers code interpreters; browsers share the same execution-role assertion.

    Unit tests for the bedrockagentcore_tool_execution_role_no_wildcard_privileges
    check."""

    def _run(self, roles=_UNSET, policies=None):
        """Import the service + check under the active mocks and execute."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = mock.MagicMock()
        # _UNSET means "the test did not care"; an explicit None means ListRoles was DENIED,
        # which is a different state from an empty account and must stay distinguishable.
        iam_client.roles = [] if roles is _UNSET else roles
        iam_client.policies = policies if policies is not None else {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_tool_execution_role_no_wildcard_privileges.bedrockagentcore_tool_execution_role_no_wildcard_privileges.bedrockagentcore_client",
                new=BedrockAgentCore(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_tool_execution_role_no_wildcard_privileges.bedrockagentcore_tool_execution_role_no_wildcard_privileges.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_tool_execution_role_no_wildcard_privileges.bedrockagentcore_tool_execution_role_no_wildcard_privileges import (
                bedrockagentcore_tool_execution_role_no_wildcard_privileges,
            )

            return (
                bedrockagentcore_tool_execution_role_no_wildcard_privileges().execute()
            )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_browser_mock)
    @mock_aws
    def test_a_browser_execution_role_is_assessed_too(self):
        """A BROWSER's execution role must be assessed, not only a code interpreter's.

        The browser arm of the collection was load-bearing with zero coverage: deleting it left all
        72 tests green while this policy went from one FAIL to no findings at all. The class
        docstring conceded "browsers share the same execution-role assertion", which is true of the
        assertion and says nothing about the collection arm that feeds it.
        """
        result = self._run(
            roles=[_Role(inline_policies=["admin"])],
            policies={f"{ROLE_ARN}:policy/admin": _Policy(ADMIN_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == BROWSER_ID

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_a_managed_policy_present_with_no_document_is_manual_not_pass(self):
        """A policy entry that EXISTS but whose document was never read must be MANUAL.

        Distinct from the absent-entry case already covered: prowler's IAM collector builds every
        Policy first and only sets `document` when GetPolicyVersion succeeds, continuing past a
        ClientError -- so a denied or throttled call leaves the entry in place with document None.
        Weakening the guard to `policy_obj is None` left 21 tests green while this reported PASS,
        certifying an unread policy document as clean.
        """
        arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/agent-sandbox-policy"
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {"PolicyName": "agent-sandbox-policy", "PolicyArn": arn}
                    ]
                )
            ],
            policies={arn: _Policy(None)},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        """No resources means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        """A ValidationException from the region must not raise; it yields no findings."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_scoped_inline_policy_passes(self):
        """A role whose only grant is action- and resource-scoped is compliant.

        The PASS sentence says "no attached or inline policy individually granting", not "does not
        grant". The qualifier is load-bearing: documents are never aggregated, so an escalation
        combination split across two of the role's policies would still reach this branch.
        """
        result = self._run(
            roles=[_Role(inline_policies=["scoped"])],
            policies={f"{ROLE_ARN}:policy/scoped": _Policy(SCOPED_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            "execution role has no attached or inline policy individually granting wildcard privileges"
            in result[0].status_extended
        )
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_admin_inline_policy_fails(self):
        """Action:* on Resource:* is administrative access.

        The FAIL sentence claims only what was measured. Documents are evaluated one at a time and
        never aggregated, so the wording is "has an attached or inline policy granting" rather than
        "grants": effective permission is the union of the Allows minus the union of the Denies, and
        a blanket Deny elsewhere on the role would not be seen here.
        """
        result = self._run(
            roles=[_Role(inline_policies=["admin"])],
            policies={f"{ROLE_ARN}:policy/admin": _Policy(ADMIN_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "administrative access" in result[0].status_extended
        assert (
            "execution role has an attached or inline policy granting wildcard privileges"
            in result[0].status_extended
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_service_wide_grant_fails(self):
        """s3:* on Resource:* is the gap check_admin_access alone does not catch."""
        result = self._run(
            roles=[_Role(inline_policies=["servicewide"])],
            policies={f"{ROLE_ARN}:policy/servicewide": _Policy(SERVICE_WIDE_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "full access to s3" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_privilege_escalation_combination_in_one_document_fails(self):
        """A complete escalation combination inside one document must FAIL.

        The document grants no service-wide access and is not Action:*, so it reaches the
        privilege escalation test rather than the two checks above it. The combination is
        PassRole plus the three AgentCore code interpreter actions, which is the escalation this
        check most exists to catch: it lets sandbox code create an interpreter, pass a role to it
        and invoke it.
        """
        result = self._run(
            roles=[_Role(inline_policies=["escalation"])],
            policies={f"{ROLE_ARN}:policy/escalation": _Policy(ESCALATION_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "allows privilege escalation" in result[0].status_extended
        assert "inline policy escalation" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_unreadable_inline_policy_document_is_manual_not_pass(self):
        """An INLINE policy whose document could not be fetched must not read as clean.

        Same reasoning as the managed-policy case, on the other branch of the same guard: an
        inline document that did not resolve is where a wildcard grant would hide, so the role
        cannot be called clean on the strength of the policies that did resolve.
        """
        result = self._run(
            roles=[_Role(inline_policies=["missing-inline"])],
            policies={},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert "inline policy missing-inline" in result[0].status_extended
        assert result[0].status_extended.endswith(".")

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_managed_full_access_policy_fails(self):
        """An AWS-managed *FullAccess policy is flagged by ARN, without a document."""
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
                            "PolicyName": "AmazonS3FullAccess",
                        }
                    ]
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "grants full access" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_denied_list_roles_is_manual_not_a_clean_account(self):
        """A denied ListRoles is an unknown inventory, not an empty one.

        Before this was guarded, `iam_client.roles or []` turned the unknown into an empty
        map, every execution role resolved to None, and the check reported on an account it
        had never read.
        """
        result = self._run(roles=None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be listed" in result[0].status_extended

    @pytest.mark.parametrize(
        "policy_arn",
        [
            "arn:aws-us-gov:iam::aws:policy/AmazonSQSFullAccess",
            "arn:aws-cn:iam::aws:policy/AmazonSQSFullAccess",
        ],
    )
    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_managed_full_access_policy_flagged_in_every_partition(self, policy_arn):
        """An AWS-managed *FullAccess policy must be caught outside the commercial partition.

        Matching an `arn:aws:iam::aws:policy/` prefix silently stopped enforcing in GovCloud
        and China. The fall-through evaluates the document instead, and it only tests
        SENSITIVE_SERVICES -- sqs is not one -- so this policy PASSed there while FAILing in
        commercial.
        """
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": policy_arn,
                            "PolicyName": "AmazonSQSFullAccess",
                        }
                    ]
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "grants full access" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_unresolvable_role_is_manual_not_fail(self):
        """A role absent from the IAM inventory is unknown: neither PASS nor FAIL.

        It must not PASS, because an unfetched role is where a wildcard grant would hide.
        It must not FAIL either: nothing about the role has been established, and the
        status_extended says as much. The two sibling checks in this PR treat an unknown
        IAM inventory as MANUAL for the same reason.
        """
        result = self._run(roles=[])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be resolved" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_unreadable_policy_document_is_manual_not_pass(self):
        """A policy whose document could not be fetched must not read as clean.

        The unfetched document is exactly where a wildcard grant would hide, and
        this role backs agent-directed sandbox code, so claiming compliance from
        the policies that happened to resolve is the worst possible default.
        """
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        # Name and ARN deliberately share no substring. With
                        # "arn:unreadable"/"unreadable" no assertion could tell which the
                        # finding used, which is why a mutation of the
                        # `PolicyName or PolicyArn` fallback survived this test.
                        {
                            "PolicyArn": "arn:aws:iam::aws:policy/Zzz9",
                            "PolicyName": "friendly-policy-name",
                        }
                    ]
                )
            ],
            policies={},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert "managed policy friendly-policy-name" in result[0].status_extended
        assert "arn:aws:iam::" not in result[0].status_extended
        assert result[0].status_extended.endswith(".")

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_wildcard_grant_outweighs_an_unreadable_policy(self):
        """A grant that was read is definite, so FAIL survives incompleteness."""
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {"PolicyArn": "arn:unreadable", "PolicyName": "unreadable"},
                        {"PolicyArn": "arn:admin", "PolicyName": "admin"},
                    ]
                )
            ],
            policies={"arn:admin": _Policy(ADMIN_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_without_role)
    @mock_aws
    def test_no_execution_role_passes(self):
        """A tool with no execution role has no permissions to over-grant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "no execution role" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_unreadable)
    @mock_aws
    def test_detail_unreadable_is_manual_not_pass(self):
        """A failed GetCodeInterpreter must not be read as "no execution role attached"."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert result[0].resource_id == RES_ID
        assert result[0].resource_arn == RES_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_violations_list_is_sorted_for_deterministic_output(self):
        """Regression test: violations are sorted so policy order doesn't affect output.

        ListAttachedRolePolicies documents no ordering, so an unchanged role with
        policies returned in different order must produce byte-identical findings.
        """
        policy_a_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/PolicyA"
        policy_b_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/PolicyB"
        policy_c_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/PolicyC"

        # Create policies that each trigger a service-wide violation
        policy_a_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}],
        }
        policy_b_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "kms:*", "Resource": "*"}],
        }
        policy_c_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        }

        # Run with policies in ABC order
        result_forward = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {"PolicyArn": policy_a_arn, "PolicyName": "PolicyA"},
                        {"PolicyArn": policy_b_arn, "PolicyName": "PolicyB"},
                        {"PolicyArn": policy_c_arn, "PolicyName": "PolicyC"},
                    ]
                )
            ],
            policies={
                policy_a_arn: _Policy(policy_a_doc),
                policy_b_arn: _Policy(policy_b_doc),
                policy_c_arn: _Policy(policy_c_doc),
            },
        )

        # Run with policies in CBA order (reversed)
        result_reversed = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {"PolicyArn": policy_c_arn, "PolicyName": "PolicyC"},
                        {"PolicyArn": policy_b_arn, "PolicyName": "PolicyB"},
                        {"PolicyArn": policy_a_arn, "PolicyName": "PolicyA"},
                    ]
                )
            ],
            policies={
                policy_a_arn: _Policy(policy_a_doc),
                policy_b_arn: _Policy(policy_b_doc),
                policy_c_arn: _Policy(policy_c_doc),
            },
        )

        # Both runs must produce byte-identical status_extended
        assert len(result_forward) == 1
        assert len(result_reversed) == 1
        assert result_forward[0].status == "FAIL"
        assert result_reversed[0].status == "FAIL"
        assert result_forward[0].status_extended == result_reversed[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_role)
    @mock_aws
    def test_unresolved_list_is_sorted_for_deterministic_output(self):
        """Regression test: unresolved policies are sorted for deterministic MANUAL findings.

        When attached policies cannot be resolved from the IAM inventory,
        ListAttachedRolePolicies documents no ordering, so the same role with
        unreadable policies in different order must produce byte-identical findings.
        """
        policy_x_arn = "arn:aws:iam::123456789012:policy/PolicyX"
        policy_y_arn = "arn:aws:iam::123456789012:policy/PolicyY"
        policy_z_arn = "arn:aws:iam::123456789012:policy/PolicyZ"

        # Run with unresolvable policies in XYZ order
        result_forward = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {"PolicyArn": policy_x_arn, "PolicyName": "PolicyX"},
                        {"PolicyArn": policy_y_arn, "PolicyName": "PolicyY"},
                        {"PolicyArn": policy_z_arn, "PolicyName": "PolicyZ"},
                    ]
                )
            ],
            policies={},  # Empty policies dict means all are unresolvable
        )

        # Run with unresolvable policies in ZYX order (reversed)
        result_reversed = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {"PolicyArn": policy_z_arn, "PolicyName": "PolicyZ"},
                        {"PolicyArn": policy_y_arn, "PolicyName": "PolicyY"},
                        {"PolicyArn": policy_x_arn, "PolicyName": "PolicyX"},
                    ]
                )
            ],
            policies={},  # Empty policies dict means all are unresolvable
        )

        # Both runs must produce byte-identical status_extended
        assert len(result_forward) == 1
        assert len(result_reversed) == 1
        assert result_forward[0].status == "MANUAL"
        assert result_reversed[0].status == "MANUAL"
        assert result_forward[0].status_extended == result_reversed[0].status_extended
