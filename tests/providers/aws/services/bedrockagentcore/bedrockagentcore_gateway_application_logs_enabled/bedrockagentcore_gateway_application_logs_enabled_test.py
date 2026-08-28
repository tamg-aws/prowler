from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

CHECK_NAME = "bedrockagentcore_gateway_application_logs_enabled"

GW_ID = "ABCDE12345"
GW_NAME = "test-gateway"
GW_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/{GW_ID}"

OTHER_GW_ID = "FGHIJ67890"
OTHER_GW_NAME = "other-gateway"
OTHER_GW_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/{OTHER_GW_ID}"

SOURCE_NAME = "test-gateway-logs-source"
SOURCE_ARN = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:delivery-source:{SOURCE_NAME}"
DESTINATION_ARN = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:delivery-destination:test-gateway-logs-destination"
DELIVERY_ARN = (
    f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:delivery:AbCdEf123456"
)


def _gateway_summary(gateway_id, name):
    """A ListGateways item. GatewaySummary carries no gatewayArn."""
    return {
        "gatewayId": gateway_id,
        "name": name,
        "status": "READY",
        "authorizerType": "CUSTOM_JWT",
        "protocolType": "MCP",
    }


def _delivery_source(name, resource_arns, log_type="APPLICATION_LOGS"):
    """Build a CloudWatch Logs delivery source dict for the given resource ARNs and log type."""
    return {
        "name": name,
        "arn": SOURCE_ARN,
        "resourceArns": resource_arns,
        "service": "bedrock-agentcore",
        "logType": log_type,
    }


def _delivery(source_name):
    """Build a CloudWatch Logs delivery dict linking the named source to a destination."""
    return {
        "id": "AbCdEf123456",
        "arn": DELIVERY_ARN,
        "deliverySourceName": source_name,
        "deliveryDestinationArn": DESTINATION_ARN,
        "deliveryDestinationType": "CWL",
    }


def _mock(gateways=None, sources=None, deliveries=None, errors=(), calls=None):
    """Build a _make_api_call replacement.

    AgentCore is not covered by moto, so the control-plane calls are patched
    here. The CloudWatch Logs delivery calls are patched too, because moto only
    ever returns empty lists for them.
    """

    def _make_call(self, operation_name, kwarg):
        """Mock AgentCore and CloudWatch Logs operations with optional error injection."""
        if calls is not None:
            calls.append(operation_name)
        if operation_name in errors:
            raise ClientError(
                {"Error": {"Code": errors[operation_name], "Message": "denied"}},
                operation_name,
            )
        if operation_name == "ListGateways":
            return {"items": gateways if gateways is not None else []}
        if operation_name == "DescribeDeliverySources":
            return {"deliverySources": sources if sources is not None else []}
        if operation_name == "DescribeDeliveries":
            return {"deliveries": deliveries if deliveries is not None else []}
        return make_api_call(self, operation_name, kwarg)

    return _make_call


class Test_bedrockagentcore_gateway_application_logs_enabled:
    """Unit tests for the bedrockagentcore_gateway_application_logs_enabled check."""

    def _run(self):
        """Import the services + check under the active mocks and execute."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        # The delivery collector only runs when this check is in scope, so the
        # expected_checks list is what switches it on.
        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=[CHECK_NAME],
            completed_checks=0,
            audit_progress=0,
        )
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"prowler.providers.aws.services.bedrockagentcore.{CHECK_NAME}.{CHECK_NAME}.bedrockagentcore_client",
                new=BedrockAgentCore(aws_provider),
            ),
            mock.patch(
                f"prowler.providers.aws.services.bedrockagentcore.{CHECK_NAME}.{CHECK_NAME}.logs_client",
                new=Logs(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_gateway_application_logs_enabled.bedrockagentcore_gateway_application_logs_enabled import (
                bedrockagentcore_gateway_application_logs_enabled,
            )

            return bedrockagentcore_gateway_application_logs_enabled().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock(gateways=[]))
    @mock_aws
    def test_no_gateways(self):
        """An account with no gateways emits nothing, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            gateways=[_gateway_summary(GW_ID, GW_NAME)],
            sources=[_delivery_source(SOURCE_NAME, [GW_ARN])],
            deliveries=[_delivery(SOURCE_NAME)],
        ),
    )
    @mock_aws
    def test_delivery_configured(self):
        """A source matched by ARN plus an attached delivery is a PASS."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == GW_ID
        assert result[0].resource_arn == GW_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert "CWL" in result[0].status_extended
        assert GW_NAME in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            gateways=[_gateway_summary(GW_ID, GW_NAME)], sources=[], deliveries=[]
        ),
    )
    @mock_aws
    def test_listed_but_no_delivery_source(self):
        """Inventories listed and empty is a definite "not configured" FAIL."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == GW_ID
        assert result[0].resource_arn == GW_ARN
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore gateway {GW_NAME} has no APPLICATION_LOGS delivery source in region {AWS_REGION_US_EAST_1}, so its application logs are not delivered."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            gateways=[_gateway_summary(GW_ID, GW_NAME)],
            sources=[_delivery_source(SOURCE_NAME, [GW_ARN])],
            deliveries=[],
        ),
    )
    @mock_aws
    def test_source_without_delivery(self):
        """A registered source with no delivery attached emits nothing: FAIL."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no delivery attached" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            gateways=[_gateway_summary(GW_ID, GW_NAME)],
            sources=[_delivery_source(SOURCE_NAME, [GW_ARN])],
            deliveries=[_delivery("an-unrelated-source")],
        ),
    )
    @mock_aws
    def test_delivery_attached_to_another_source(self):
        """A delivery for some other source does not deliver this one.

        deliverySourceName is the only link between a delivery and its source,
        so a Region that has deliveries at all must not credit a source that
        none of them names.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no delivery attached" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            gateways=[_gateway_summary(GW_ID, GW_NAME)],
            sources=[_delivery_source(SOURCE_NAME, [GW_ARN], log_type="TRACES")],
            deliveries=[_delivery(SOURCE_NAME)],
        ),
    )
    @mock_aws
    def test_traces_only_is_not_application_logs(self):
        """A TRACES delivery carries spans, not the call trail, so it FAILs."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no APPLICATION_LOGS delivery source" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            gateways=[_gateway_summary(GW_ID, GW_NAME)],
            sources=[_delivery_source(SOURCE_NAME, [OTHER_GW_ARN])],
            deliveries=[_delivery(SOURCE_NAME)],
        ),
    )
    @mock_aws
    def test_delivery_for_a_different_gateway(self):
        """Another gateway's delivery must not credit this one."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_arn == GW_ARN
        assert "no APPLICATION_LOGS delivery source" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            gateways=[_gateway_summary(GW_ID, GW_NAME)],
            errors={"DescribeDeliverySources": "AccessDeniedException"},
        ),
    )
    @mock_aws
    def test_delivery_sources_denied_is_manual_not_pass(self):
        """A denied DescribeDeliverySources must not read as either state."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_arn == GW_ARN
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore gateway {GW_NAME} log delivery could not be determined in region {AWS_REGION_US_EAST_1} because the CloudWatch Logs delivery sources could not be listed; verify manually that its application logs are delivered."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            gateways=[_gateway_summary(GW_ID, GW_NAME)],
            sources=[_delivery_source(SOURCE_NAME, [GW_ARN])],
            errors={"DescribeDeliveries": "AccessDeniedException"},
        ),
    )
    @mock_aws
    def test_deliveries_denied_is_manual_not_fail(self):
        """A readable source with an unreadable delivery list is still unknown.

        The message must name the deliveries, not the sources, so a reader can
        tell which permission is missing.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "the CloudWatch Logs deliveries could not be listed" in (
            result[0].status_extended
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(errors={"ListGateways": "AccessDeniedException"}),
    )
    @mock_aws
    def test_gateways_denied_is_manual_not_silence(self):
        """A denied ListGateways must not look like an account with no gateways."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "gateway/unknown"
        assert "could not be listed" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(errors={"ListGateways": "ValidationException"}),
    )
    @mock_aws
    def test_region_not_supported(self):
        """AgentCore absent from the Region is a definite "no gateways"."""
        assert self._run() == []

    def test_collector_skipped_when_check_out_of_scope(self):
        """The delivery calls are only paid for when this check is in scope.

        Without the expected_checks gate every audit would pay two extra
        paginated calls per Region for an inventory nothing reads.
        """
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        calls = []
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=["cloudwatch_log_group_kms_encryption_enabled"],
            completed_checks=0,
            audit_progress=0,
        )
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "botocore.client.BaseClient._make_api_call", new=_mock(calls=calls)
            ),
            mock_aws(),
        ):
            logs = Logs(aws_provider)

        assert "DescribeDeliverySources" not in calls
        assert "DescribeDeliveries" not in calls
        assert logs.delivery_sources == {}
        assert logs.deliveries == {}

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            gateways=[
                _gateway_summary(GW_ID, GW_NAME),
                _gateway_summary(OTHER_GW_ID, OTHER_GW_NAME),
            ],
            sources=[_delivery_source(SOURCE_NAME, [GW_ARN])],
            deliveries=[_delivery(SOURCE_NAME)],
        ),
    )
    @mock_aws
    def test_multiple_gateways_split(self):
        """Two gateways yield two findings: only the delivered one PASSes."""
        result = self._run()
        assert len(result) == 2
        by_arn = {report.resource_arn: report for report in result}
        assert set(by_arn) == {GW_ARN, OTHER_GW_ARN}
        assert by_arn[GW_ARN].status == "PASS"
        assert by_arn[OTHER_GW_ARN].status == "FAIL"
        assert [report.status for report in result].count("PASS") == 1
        assert [report.status for report in result].count("FAIL") == 1
