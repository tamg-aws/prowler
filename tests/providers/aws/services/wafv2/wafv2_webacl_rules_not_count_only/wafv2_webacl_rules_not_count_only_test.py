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

CHECK_PATH = "prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only.wafv2_client"

VISIBILITY = {
    "SampledRequestsEnabled": True,
    "CloudWatchMetricsEnabled": True,
    "MetricName": "web-acl-test-metric",
}

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call

FM_RG_NAME = "test-firewall-manager-rule-group"
FM_RG_ARN = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test-firewall-manager-rule-group"


def _byte_match_rule(name: str, priority: int, action: dict) -> dict:
    """A standalone rule, whose effective action comes from its own Action."""
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


def _managed_rule_group_rule(name: str, priority: int, override: dict) -> dict:
    """A rule group reference, whose effective action comes from OverrideAction."""
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
            }
        },
        "OverrideAction": override,
        "VisibilityConfig": VISIBILITY,
    }


def _create_web_acl(name: str, rules: list, default_action: dict = None) -> dict:
    """Create a REGIONAL Web ACL in moto, allowing by default unless the caller overrides it.

    The default action matters to this check: a Web ACL that blocks by default enforces without any
    rule needing a blocking action, so `default_action` is a parameter rather than a constant.
    """
    wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
    return wafv2.create_web_acl(
        Name=name,
        Scope="REGIONAL",
        DefaultAction=default_action or {"Allow": {}},
        Rules=rules,
        VisibilityConfig=VISIBILITY,
        Tags=[{"Key": "Name", "Value": name}],
    )["Summary"]


# Firewall Manager pushes rule groups outside WebACL.Rules, and moto cannot create them, so the
# only way to exercise that path is a stubbed GetWebACL response. The group is overridden to
# Count, which is the FAIL condition.
def mock_make_api_call(self, operation_name, kwarg):
    """Serve a Web ACL whose only rule group is a Firewall Manager one overridden to Count."""
    if operation_name == "ListWebACLs":
        return {"WebACLs": [{"Name": FM_RG_NAME, "Id": FM_RG_NAME, "ARN": FM_RG_ARN}]}
    elif operation_name == "GetWebACL":
        return {
            "WebACL": {
                "Name": FM_RG_NAME,
                "Id": FM_RG_NAME,
                "ARN": FM_RG_ARN,
                "DefaultAction": {"Allow": {}},
                "PostProcessFirewallManagerRuleGroups": [
                    {
                        "Name": FM_RG_NAME,
                        "Priority": 1,
                        "FirewallManagerStatement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesCommonRuleSet",
                            }
                        },
                        "OverrideAction": {"Count": {}},
                        "VisibilityConfig": VISIBILITY,
                    }
                ],
            }
        }
    elif operation_name == "ListResourcesForWebACL":
        return {"ResourceArns": [FM_RG_ARN]}
    elif operation_name == "ListTagsForResource":
        return {
            "TagInfoForResource": {
                "ResourceARN": FM_RG_ARN,
                "TagList": [{"Key": "Name", "Value": FM_RG_NAME}],
            }
        }
    return orig(self, operation_name, kwarg)


def mock_make_api_call_list_denied(self, operation_name, kwarg):
    """Deny ListWebACLs, so no Web ACL is collected and the check has nothing to report on."""
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


class Test_wafv2_webacl_rules_not_count_only:
    @mock_aws
    def test_no_web_acls(self):
        """An account with no Web ACLs produces no reports, not a PASS for the account."""
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_web_acl_blocking_rule(self):
        """A single rule with Action Block must PASS.

        Also pins the report's identity fields -- resource id, ARN, region and tags -- which every
        other case in this file takes for granted.
        """
        waf = _create_web_acl(
            "test-blocking", [_byte_match_rule("block-it", 1, {"Block": {}})]
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
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} has at least one rule or rule group that can block matching requests."
            )
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf["Name"]}]

    @mock_aws
    def test_web_acl_rule_group_not_overridden(self):
        """OverrideAction None keeps the rule group's own Block actions."""
        waf = _create_web_acl(
            "test-override-none",
            [_managed_rule_group_rule("crs", 1, {"None": {}})],
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
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} has at least one rule or rule group that can block matching requests."
            )

    @mock_aws
    def test_web_acl_mixed_blocking_and_count_only(self):
        """Tuning one rule group in Count while another blocks is a normal posture, not a finding."""
        waf = _create_web_acl(
            "test-mixed",
            [
                _byte_match_rule("block-it", 1, {"Block": {}}),
                _managed_rule_group_rule("crs-being-tuned", 2, {"Count": {}}),
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
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} has at least one rule or rule group that can block matching requests."
            )

    @mock_aws
    def test_web_acl_all_rules_count_only(self):
        """FAIL: a standalone Count rule plus a rule group overridden to Count blocks nothing."""
        waf = _create_web_acl(
            "test-count-only",
            [
                _byte_match_rule("count-it", 1, {"Count": {}}),
                _managed_rule_group_rule("crs", 2, {"Count": {}}),
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
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} only counts matching requests, so no rule or rule group blocks them."
            )
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_web_acl_count_only_but_default_action_block(self):
        """An allow-list web ACL enforces through DefaultAction Block, so Count rules are fine."""
        waf = _create_web_acl(
            "test-default-block",
            [_byte_match_rule("count-it", 1, {"Count": {}})],
            default_action={"Block": {}},
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
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf['Name']} blocks requests by default, so its rules do not need a blocking action."
            )

    @mock_aws
    def test_web_acl_listed_but_empty(self):
        """A web ACL with zero rules is out of scope -- wafv2_webacl_with_rules reports it."""
        _create_web_acl("test-empty", [])

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            service = WAFv2(aws_provider)
            assert len(service.web_acls) == 1

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 0

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_web_acl_firewall_manager_rule_group_count_only(self):
        """A Web ACL whose only rule group is a Firewall Manager one in Count must FAIL.

        The group is absent from WebACL.Rules, so a check reading only that list would see no rules
        at all and skip the Web ACL instead of reporting that nothing blocks.
        """
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {FM_RG_NAME} only counts matching requests, so no rule or rule group blocks them."
            )
            assert result[0].resource_arn == FM_RG_ARN

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_list_denied
    )
    @mock_aws
    def test_list_web_acls_access_denied(self):
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
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 0
            assert not any(report.status == "PASS" for report in result)

    @mock_aws
    def test_region_without_web_acls(self):
        """Auditing only a region with no web ACLs yields no findings, not a PASS."""
        _create_web_acl("test-us-east-1", [_byte_match_rule("b", 1, {"Block": {}})])

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_SOUTH_2])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_multiple_web_acls_pass_and_fail(self):
        """Three Web ACLs yield two reports: the rule-less one is skipped, not reported.

        Blocking maps to PASS and count-only to FAIL, while the empty Web ACL produces no report at
        all because wafv2_webacl_with_rules owns that case.
        """
        blocking = _create_web_acl(
            "test-multi-blocking", [_byte_match_rule("block-it", 1, {"Block": {}})]
        )
        count_only = _create_web_acl(
            "test-multi-count", [_managed_rule_group_rule("crs", 1, {"Count": {}})]
        )
        # Out of scope: no rules at all.
        _create_web_acl("test-multi-empty", [])

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rules_not_count_only.wafv2_webacl_rules_not_count_only import (
                wafv2_webacl_rules_not_count_only,
            )

            check = wafv2_webacl_rules_not_count_only()
            result = check.execute()

            assert len(result) == 2
            by_arn = {report.resource_arn: report for report in result}
            assert by_arn[blocking["ARN"]].status == "PASS"
            assert by_arn[count_only["ARN"]].status == "FAIL"
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
