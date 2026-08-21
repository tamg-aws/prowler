from unittest.mock import patch

import botocore
from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call

UNREADABLE_ACL_NAME = "unreadable-web-acl"
UNREADABLE_ACL_ARN = (
    "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/unreadable-web-acl"
)
FM_ACL_NAME = "firewall-manager-web-acl"
FM_ACL_ARN = (
    "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/firewall-manager-web-acl"
)
VISIBILITY = {
    "SampledRequestsEnabled": True,
    "CloudWatchMetricsEnabled": True,
    "MetricName": "web-acl-test-metric",
}


def mock_make_api_call_firewall_manager_anti_ddos(self, operation_name, kwarg):
    """Firewall Manager pushes rule groups outside WebACL.Rules and moto cannot create them."""
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [{"Name": FM_ACL_NAME, "Id": FM_ACL_NAME, "ARN": FM_ACL_ARN}]
        }
    if operation_name == "GetWebACL":
        return {
            "WebACL": {
                "Name": FM_ACL_NAME,
                "Id": FM_ACL_NAME,
                "ARN": FM_ACL_ARN,
                "DefaultAction": {"Allow": {}},
                "PreProcessFirewallManagerRuleGroups": [
                    {
                        "Name": "fm-anti-ddos",
                        "Priority": 1,
                        "FirewallManagerStatement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesAntiDDoSRuleSet",
                            }
                        },
                        "OverrideAction": {"None": {}},
                        "VisibilityConfig": VISIBILITY,
                    }
                ],
            }
        }
    return orig(self, operation_name, kwarg)


def mock_make_api_call_get_web_acl_denied(self, operation_name, kwarg):
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {
                    "Name": UNREADABLE_ACL_NAME,
                    "Id": UNREADABLE_ACL_NAME,
                    "ARN": UNREADABLE_ACL_ARN,
                }
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


def mock_make_api_call_get_web_acl_empty_response(self, operation_name, kwarg):
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {
                    "Name": UNREADABLE_ACL_NAME,
                    "Id": UNREADABLE_ACL_NAME,
                    "ARN": UNREADABLE_ACL_ARN,
                }
            ]
        }
    if operation_name == "GetWebACL":
        return {"LockToken": "0e2b9f7a-0000-0000-0000-1f4e6c8d5a3b"}
    return orig(self, operation_name, kwarg)


class Test_WAFv2_Service:
    # Test WAFv2 Service
    @mock_aws
    def test_service(self):
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        assert wafv2.service == "wafv2"

    # Test WAFv2 Client
    @mock_aws
    def test_client(self):
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        for regional_client in wafv2.regional_clients.values():
            assert regional_client.__class__.__name__ == "WAFV2"

    # Test WAFv2 Session
    @mock_aws
    def test__get_session__(self):
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        assert wafv2.session.__class__.__name__ == "Session"

    # Test WAFv2 Describe Regional Web ACLs
    @mock_aws
    def test_list_web_acls_regional(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        assert len(wafv2.web_acls) == 1
        assert wafv2.web_acls[waf_arn].name == waf["Name"]
        assert wafv2.web_acls[waf_arn].region == AWS_REGION_EU_WEST_1
        assert wafv2.web_acls[waf_arn].arn == waf["ARN"]
        assert wafv2.web_acls[waf_arn].id == waf["Id"]

    # Test WAFv2 Describe Global Web ACLs
    @mock_aws
    def test_list_web_acls_global(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2.create_web_acl(
            Scope="CLOUDFRONT",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        wafv2 = WAFv2(aws_provider)
        assert len(wafv2.web_acls) == 1
        assert wafv2.web_acls[waf_arn].name == waf["Name"]
        assert wafv2.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert wafv2.web_acls[waf_arn].arn == waf["ARN"]
        assert wafv2.web_acls[waf_arn].id == waf["Id"]

    # Test WAFv2 Describe Web ACLs Resources
    @mock_aws
    def test_list_resources_for_web_acl(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        waf_arn = waf["ARN"]
        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}a",
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}b",
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        wafv2.associate_web_acl(WebACLArn=waf["ARN"], ResourceArn=lb["LoadBalancerArn"])
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        wafv2.web_acls[waf_arn].albs.append(lb["LoadBalancerArn"])
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].albs) == 1
        assert lb["LoadBalancerArn"] in wafv2.web_acls[waf_arn].albs

    # Test WAFv2 describe Web user pools
    @mock_aws
    def test_list_resources_for_web_user_pools(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        cognito = client("cognito-idp", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        waf_arn = waf["ARN"]
        user_pool = cognito.create_user_pool(PoolName="my-user-pool")["UserPool"]
        wafv2.associate_web_acl(WebACLArn=waf["ARN"], ResourceArn=user_pool["Arn"])
        # WAFv2 client for this test class
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        wafv2.web_acls[waf_arn].user_pools.append(user_pool["Arn"])
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].user_pools) == 1
        assert user_pool["Arn"] in wafv2.web_acls[waf_arn].user_pools

    @mock_aws
    def test_list_tags(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        wafv2.tag_resource(
            ResourceARN=waf["ARN"], Tags=[{"Key": "Name", "Value": "my-web-acl"}]
        )
        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].tags) == 1
        assert wafv2.web_acls[waf_arn].tags[0]["Key"] == "Name"
        assert wafv2.web_acls[waf_arn].tags[0]["Value"] == "my-web-acl"

    @mock_aws
    def test_get_web_acl(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "rule-on",
                    "Priority": 1,
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": "test",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "web-acl-test-metric",
                    },
                }
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]

        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].rules) == 1
        assert wafv2.web_acls[waf_arn].rules[0].name == "rule-on"
        assert wafv2.web_acls[waf_arn].rules[0].cloudwatch_metrics_enabled

    @mock_aws
    def test_get_web_acl_rule_actions(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        visibility = {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "web-acl-test-metric",
        }
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Block": {}},
            Rules=[
                {
                    "Name": "count-rule",
                    "Priority": 1,
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": "test",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "Action": {"Count": {}},
                    "VisibilityConfig": visibility,
                },
                {
                    "Name": "block-rule",
                    "Priority": 2,
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": "test",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "Action": {"Block": {}},
                    "VisibilityConfig": visibility,
                },
                {
                    "Name": "overridden-rule-group",
                    "Priority": 3,
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesCommonRuleSet",
                        }
                    },
                    "OverrideAction": {"Count": {}},
                    "VisibilityConfig": visibility,
                },
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]

        waf_arn = waf["ARN"]
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)

        web_acl = wafv2.web_acls[waf_arn]
        assert web_acl.default_action_block
        # A ManagedRuleGroupStatement carries no RuleGroupReferenceStatement ARN, so it is bucketed
        # into rules rather than rule_groups.
        assert len(web_acl.rules) == 3
        rules = {rule.name: rule for rule in web_acl.rules}

        assert rules["count-rule"].action == "Count"
        assert not rules["count-rule"].override_action_count
        assert not rules["count-rule"].is_enforcing

        assert rules["block-rule"].action == "Block"
        assert rules["block-rule"].is_enforcing

        assert rules["overridden-rule-group"].action is None
        assert rules["overridden-rule-group"].override_action_count
        assert not rules["overridden-rule-group"].is_enforcing

    @mock_aws
    def test_get_web_acl_managed_rule_group_identity(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "anti-ddos",
                    "Priority": 1,
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesAntiDDoSRuleSet",
                            "ManagedRuleGroupConfigs": [
                                {
                                    "AWSManagedRulesAntiDDoSRuleSet": {
                                        "ClientSideActionConfig": {
                                            "Challenge": {"UsageOfAction": "ENABLED"}
                                        },
                                        "SensitivityToBlock": "HIGH",
                                    }
                                }
                            ],
                        }
                    },
                    "OverrideAction": {"None": {}},
                    "VisibilityConfig": VISIBILITY,
                },
                {
                    "Name": "byte-match",
                    "Priority": 2,
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": "test",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "Action": {"Block": {}},
                    "VisibilityConfig": VISIBILITY,
                },
            ],
            VisibilityConfig=VISIBILITY,
        )["Summary"]

        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)

        web_acl = wafv2.web_acls[waf["ARN"]]
        assert web_acl.rules_retrieved is True
        rules = {rule.name: rule for rule in web_acl.rules}

        assert rules["anti-ddos"].managed_rule_group_vendor == "AWS"
        assert (
            rules["anti-ddos"].managed_rule_group_name
            == "AWSManagedRulesAntiDDoSRuleSet"
        )
        assert rules["anti-ddos"].is_enforcing

        # A statement that is not a ManagedRuleGroupStatement leaves both fields unset.
        assert rules["byte-match"].managed_rule_group_vendor is None
        assert rules["byte-match"].managed_rule_group_name is None

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_firewall_manager_anti_ddos,
    )
    @mock_aws
    def test_get_web_acl_firewall_manager_managed_rule_group_identity(self):
        aws = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        wafv2 = WAFv2(aws)

        web_acl = wafv2.web_acls[FM_ACL_ARN]
        assert web_acl.rules_retrieved is True
        assert web_acl.rules == []
        rule_groups = {rule.name: rule for rule in web_acl.rule_groups}

        assert rule_groups["fm-anti-ddos"].managed_rule_group_vendor == "AWS"
        assert (
            rule_groups["fm-anti-ddos"].managed_rule_group_name
            == "AWSManagedRulesAntiDDoSRuleSet"
        )
        assert not rule_groups["fm-anti-ddos"].override_action_count
        assert rule_groups["fm-anti-ddos"].is_enforcing

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_get_web_acl_denied,
    )
    @mock_aws
    def test_get_web_acl_denied_leaves_rules_unretrieved(self):
        """A denied GetWebACL must not look like a web ACL with zero rules."""
        aws = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        wafv2 = WAFv2(aws)

        web_acl = wafv2.web_acls[UNREADABLE_ACL_ARN]
        assert web_acl.rules_retrieved is None
        assert web_acl.rules == []
        assert web_acl.rule_groups == []

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_get_web_acl_empty_response,
    )
    @mock_aws
    def test_get_web_acl_without_webacl_structure_leaves_rules_unretrieved(self):
        """A GetWebACL response carrying no WebACL structure says nothing about the rules."""
        aws = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        wafv2 = WAFv2(aws)

        web_acl = wafv2.web_acls[UNREADABLE_ACL_ARN]
        assert web_acl.rules_retrieved is None
        assert web_acl.rules == []
