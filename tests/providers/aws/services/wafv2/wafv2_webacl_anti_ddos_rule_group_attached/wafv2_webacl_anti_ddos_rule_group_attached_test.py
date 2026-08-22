from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_SOUTH_2,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_PATH = "prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_client"

ANTI_DDOS = "AWSManagedRulesAntiDDoSRuleSet"

VISIBILITY = {
    "SampledRequestsEnabled": True,
    "CloudWatchMetricsEnabled": True,
    "MetricName": "web-acl-test-metric",
}

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call

FM_ACL_NAME = "test-firewall-manager-anti-ddos"
FM_ACL_ARN = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test-firewall-manager-anti-ddos"
DENIED_ACL_NAME = "test-get-web-acl-denied"
DENIED_ACL_ARN = (
    "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test-get-web-acl-denied"
)


def _managed_rule_group_rule(
    name: str,
    priority: int,
    override: dict,
    vendor: str = "AWS",
    group: str = ANTI_DDOS,
    scope_down: dict = None,
) -> dict:
    statement = {"VendorName": vendor, "Name": group}
    if scope_down:
        statement["ScopeDownStatement"] = scope_down
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"ManagedRuleGroupStatement": statement},
        "OverrideAction": override,
        "VisibilityConfig": VISIBILITY,
    }


def _byte_match_rule(name: str, priority: int, action: dict) -> dict:
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {
            "ByteMatchStatement": {
                "SearchString": "test",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                "PositionalConstraint": "CONTAINS",
            }
        },
        "Action": action,
        "VisibilityConfig": VISIBILITY,
    }


def _create_web_acl(name: str, rules: list) -> dict:
    wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
    return wafv2.create_web_acl(
        Name=name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        Rules=rules,
        VisibilityConfig=VISIBILITY,
        Tags=[{"Key": "Name", "Value": name}],
    )["Summary"]


def _fm_response(override: dict) -> dict:
    return {
        "WebACL": {
            "Name": FM_ACL_NAME,
            "Id": FM_ACL_NAME,
            "ARN": FM_ACL_ARN,
            "DefaultAction": {"Allow": {}},
            "PostProcessFirewallManagerRuleGroups": [
                {
                    "Name": "fm-anti-ddos",
                    "Priority": 1,
                    "FirewallManagerStatement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": ANTI_DDOS,
                        }
                    },
                    "OverrideAction": override,
                    "VisibilityConfig": VISIBILITY,
                }
            ],
        }
    }


# Firewall Manager pushes rule groups outside WebACL.Rules and moto cannot create them, so a
# stubbed GetWebACL response is the only way to exercise that path.
def mock_make_api_call_fm_enforcing(self, operation_name, kwarg):
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [{"Name": FM_ACL_NAME, "Id": FM_ACL_NAME, "ARN": FM_ACL_ARN}]
        }
    if operation_name == "GetWebACL":
        return _fm_response({"None": {}})
    return orig(self, operation_name, kwarg)


def mock_make_api_call_fm_count_only(self, operation_name, kwarg):
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [{"Name": FM_ACL_NAME, "Id": FM_ACL_NAME, "ARN": FM_ACL_ARN}]
        }
    if operation_name == "GetWebACL":
        return _fm_response({"Count": {}})
    return orig(self, operation_name, kwarg)


def mock_make_api_call_get_web_acl_denied(self, operation_name, kwarg):
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"Name": DENIED_ACL_NAME, "Id": DENIED_ACL_NAME, "ARN": DENIED_ACL_ARN}
            ]
        }
    if operation_name == "GetWebACL":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "User is not authorized to perform wafv2:GetWebACL",
                }
            },
            operation_name,
        )
    return orig(self, operation_name, kwarg)


def mock_make_api_call_list_denied(self, operation_name, kwarg):
    if operation_name == "ListWebACLs":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "WAFInvalidPermissionPolicyException",
                    "Message": "User is not authorized to perform wafv2:ListWebACLs",
                }
            },
            operation_name,
        )
    return orig(self, operation_name, kwarg)


class Test_wafv2_webacl_anti_ddos_rule_group_attached:
    @mock_aws
    def test_no_web_acls(self):
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_anti_ddos_rule_group_enforcing(self):
        waf = _create_web_acl(
            "test-anti-ddos-enforcing",
            [_managed_rule_group_rule("anti-ddos", 1, {"None": {}})],
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} uses the {ANTI_DDOS} rule group and can challenge or block application-layer DDoS traffic."
            )
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf["Name"]}]

    @mock_aws
    def test_anti_ddos_rule_group_with_scope_down_statement(self):
        """A ScopeDownStatement narrows what the group inspects but keeps it at the top level."""
        waf = _create_web_acl(
            "test-anti-ddos-scope-down",
            [
                _managed_rule_group_rule(
                    "anti-ddos",
                    1,
                    {"None": {}},
                    scope_down={
                        "ByteMatchStatement": {
                            "SearchString": "/api/",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "STARTS_WITH",
                        }
                    },
                )
            ],
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} uses the {ANTI_DDOS} rule group and can challenge or block application-layer DDoS traffic."
            )

    @mock_aws
    def test_anti_ddos_rule_group_overridden_to_count(self):
        """FAIL even though another rule blocks: the anti-DDoS group itself is inert."""
        waf = _create_web_acl(
            "test-anti-ddos-count",
            [
                _managed_rule_group_rule("anti-ddos", 1, {"Count": {}}),
                _byte_match_rule("block-it", 2, {"Block": {}}),
            ],
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} uses the {ANTI_DDOS} rule group but overrides it to Count, so application-layer DDoS traffic is measured and then served."
            )
            assert result[0].resource_arn == waf["ARN"]

    @mock_aws
    def test_one_enforcing_anti_ddos_group_among_counted_ones_passes(self):
        """Two references to the group, one enforcing: PASS.

        A web ACL can carry the anti-DDoS group twice -- typically one enforcing copy plus
        a second being tuned in Count. The check uses any(), not all(): one enforcing copy
        is sufficient protection. Under all() this configuration reports a false FAIL, and
        no other fixture here gives a single web ACL two anti-DDoS references.
        """
        waf = _create_web_acl(
            "test-anti-ddos-mixed",
            [
                _managed_rule_group_rule("anti-ddos-tuning", 1, {"Count": {}}),
                _managed_rule_group_rule("anti-ddos-live", 2, {"None": {}}),
            ],
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            result = wafv2_webacl_anti_ddos_rule_group_attached().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == waf["Id"]

    @mock_aws
    def test_other_managed_rule_group_only(self):
        waf = _create_web_acl(
            "test-common-rule-set-only",
            [
                _managed_rule_group_rule(
                    "crs", 1, {"None": {}}, group="AWSManagedRulesCommonRuleSet"
                )
            ],
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} does not use the {ANTI_DDOS} rule group, so it has no application-layer DDoS mitigation beyond the always-on baseline."
            )

    @mock_aws
    def test_same_group_name_from_another_vendor(self):
        """A third-party group that reuses the name is not the AWS anti-DDoS rule group."""
        waf = _create_web_acl(
            "test-other-vendor",
            [
                _managed_rule_group_rule(
                    "lookalike", 1, {"None": {}}, vendor="ThirdParty"
                )
            ],
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} does not use the {ANTI_DDOS} rule group, so it has no application-layer DDoS mitigation beyond the always-on baseline."
            )

    @mock_aws
    def test_web_acl_with_no_rules(self):
        """A readable web ACL with zero rules genuinely has no anti-DDoS rule group."""
        waf = _create_web_acl("test-empty", [])

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} does not use the {ANTI_DDOS} rule group, so it has no application-layer DDoS mitigation beyond the always-on baseline."
            )

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_fm_enforcing
    )
    @mock_aws
    def test_firewall_manager_anti_ddos_rule_group_enforcing(self):
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {FM_ACL_NAME} uses the {ANTI_DDOS} rule group and can challenge or block application-layer DDoS traffic."
            )
            assert result[0].resource_arn == FM_ACL_ARN

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_fm_count_only,
    )
    @mock_aws
    def test_firewall_manager_anti_ddos_rule_group_count_only(self):
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {FM_ACL_NAME} uses the {ANTI_DDOS} rule group but overrides it to Count, so application-layer DDoS traffic is measured and then served."
            )

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_get_web_acl_denied,
    )
    @mock_aws
    def test_get_web_acl_denied_is_manual(self):
        """Unreadable rules must not be reported as a missing rule group, nor as compliant."""
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {DENIED_ACL_NAME} rules could not be retrieved, so whether the {ANTI_DDOS} rule group is attached cannot be determined."
            )
            assert result[0].resource_arn == DENIED_ACL_ARN
            assert not any(report.status == "PASS" for report in result)
            assert not any(report.status == "FAIL" for report in result)

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_list_denied
    )
    @mock_aws
    def test_list_web_acls_denied(self):
        """A denied ListWebACLs must not be reported as a compliant web ACL."""
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 0
            assert not any(report.status == "PASS" for report in result)

    @mock_aws
    def test_region_without_web_acls(self):
        _create_web_acl(
            "test-us-east-1", [_managed_rule_group_rule("anti-ddos", 1, {"None": {}})]
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_SOUTH_2])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_multiple_web_acls_pass_and_fail(self):
        protected = _create_web_acl(
            "test-multi-protected",
            [_managed_rule_group_rule("anti-ddos", 1, {"None": {}})],
        )
        counted = _create_web_acl(
            "test-multi-counted",
            [_managed_rule_group_rule("anti-ddos", 1, {"Count": {}})],
        )
        missing = _create_web_acl(
            "test-multi-missing", [_byte_match_rule("block-it", 1, {"Block": {}})]
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_anti_ddos_rule_group_attached.wafv2_webacl_anti_ddos_rule_group_attached import (
                wafv2_webacl_anti_ddos_rule_group_attached,
            )

            check = wafv2_webacl_anti_ddos_rule_group_attached()
            result = check.execute()

            assert len(result) == 3
            by_arn = {report.resource_arn: report for report in result}
            assert by_arn[protected["ARN"]].status == "PASS"
            assert by_arn[counted["ARN"]].status == "FAIL"
            assert by_arn[missing["ARN"]].status == "FAIL"
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 2
