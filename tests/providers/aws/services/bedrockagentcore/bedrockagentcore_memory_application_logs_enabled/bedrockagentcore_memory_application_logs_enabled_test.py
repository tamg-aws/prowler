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

CHECK_NAME = "bedrockagentcore_memory_application_logs_enabled"

# The id shape a real account holds: the caller's name plus a service suffix.
MEM_ID = "test_agent_memory-XsXrjbBycH"
MEM_NAME = "test_agent_memory"
MEM_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:memory/{MEM_ID}"

OTHER_MEM_ID = "other_agent_memory-0oKfjr5F5g"
OTHER_MEM_NAME = "other_agent_memory"
OTHER_MEM_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:memory/{OTHER_MEM_ID}"

# A memory that was deleted while its delivery source and delivery survived it.
# This is the state a real account was found in, and the source it leaves behind
# must not credit any of the memory resources that still exist.
DELETED_MEM_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:memory/deleted_agent_mem-XAKdWz6O8A"

SOURCE_NAME = f"{MEM_ID}-logs-source"
SOURCE_ARN = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:delivery-source:{SOURCE_NAME}"
DESTINATION_ARN = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:delivery-destination:{MEM_ID}-logs-destination"
DELIVERY_ARN = (
    f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:delivery:AbCdEf123456"
)


def _memory_summary(memory_id, memory_arn):
    """A ListMemories item. MemorySummary carries no name."""
    return {
        "id": memory_id,
        "arn": memory_arn,
        "status": "ACTIVE",
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


def _mock(memories=None, sources=None, deliveries=None, errors=(), calls=None):
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
        if operation_name == "ListMemories":
            return {"memories": memories if memories is not None else []}
        if operation_name == "GetMemory":
            memory_id = kwarg["memoryId"]
            return {
                "memory": {
                    "id": memory_id,
                    # The name is what GetMemory adds over the listing.
                    "name": memory_id.rsplit("-", 1)[0],
                }
            }
        if operation_name == "DescribeDeliverySources":
            return {"deliverySources": sources if sources is not None else []}
        if operation_name == "DescribeDeliveries":
            return {"deliveries": deliveries if deliveries is not None else []}
        return make_api_call(self, operation_name, kwarg)

    return _make_call


class Test_bedrockagentcore_memory_application_logs_enabled:
    """Unit tests for the bedrockagentcore_memory_application_logs_enabled check."""

    def _run(self):
        """Import the services + check under the active mocks and execute."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        # The delivery collector only runs when a check that reads it is in
        # scope, so the expected_checks list is what switches it on.
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
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_memory_application_logs_enabled.bedrockagentcore_memory_application_logs_enabled import (
                bedrockagentcore_memory_application_logs_enabled,
            )

            return bedrockagentcore_memory_application_logs_enabled().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock(memories=[]))
    @mock_aws
    def test_no_memories(self):
        """An account with no memory resources emits nothing, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            memories=[_memory_summary(MEM_ID, MEM_ARN)],
            sources=[_delivery_source(SOURCE_NAME, [MEM_ARN])],
            deliveries=[_delivery(SOURCE_NAME)],
        ),
    )
    @mock_aws
    def test_delivery_configured(self):
        """A source matched by ARN plus an attached delivery is a PASS."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == MEM_ID
        assert result[0].resource_arn == MEM_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert "CWL" in result[0].status_extended
        assert MEM_NAME in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            memories=[_memory_summary(MEM_ID, MEM_ARN)], sources=[], deliveries=[]
        ),
    )
    @mock_aws
    def test_listed_but_no_delivery_source(self):
        """Inventories listed and empty is a definite "not configured" FAIL."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == MEM_ID
        assert result[0].resource_arn == MEM_ARN
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore memory {MEM_NAME} has no APPLICATION_LOGS delivery source in region {AWS_REGION_US_EAST_1}, so its application logs are not delivered."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            memories=[_memory_summary(MEM_ID, MEM_ARN)],
            sources=[_delivery_source(SOURCE_NAME, [MEM_ARN])],
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
            memories=[_memory_summary(MEM_ID, MEM_ARN)],
            sources=[_delivery_source(SOURCE_NAME, [MEM_ARN])],
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
            memories=[_memory_summary(MEM_ID, MEM_ARN)],
            sources=[_delivery_source(SOURCE_NAME, [MEM_ARN], log_type="TRACES")],
            deliveries=[_delivery(SOURCE_NAME)],
        ),
    )
    @mock_aws
    def test_traces_only_is_not_application_logs(self):
        """A TRACES delivery carries the memory spans, not the job records.

        Both log types are registered against the same memory ARN in real
        accounts, so the log type is the only thing separating them.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no APPLICATION_LOGS delivery source" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            memories=[_memory_summary(MEM_ID, MEM_ARN)],
            sources=[
                _delivery_source(SOURCE_NAME, [DELETED_MEM_ARN]),
                _delivery_source(
                    f"{SOURCE_NAME}-traces", [DELETED_MEM_ARN], log_type="TRACES"
                ),
            ],
            deliveries=[_delivery(SOURCE_NAME), _delivery(f"{SOURCE_NAME}-traces")],
        ),
    )
    @mock_aws
    def test_delivery_for_a_deleted_memory(self):
        """An orphaned source must not credit a memory that still exists.

        Deleting a memory leaves its delivery source and delivery behind, so an
        account can hold a complete APPLICATION_LOGS configuration that covers
        no live memory at all.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_arn == MEM_ARN
        assert "no APPLICATION_LOGS delivery source" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            memories=[_memory_summary(MEM_ID, MEM_ARN)],
            errors={"DescribeDeliverySources": "AccessDeniedException"},
        ),
    )
    @mock_aws
    def test_delivery_sources_denied_is_manual_not_pass(self):
        """A denied DescribeDeliverySources must not read as either state."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_arn == MEM_ARN
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore memory {MEM_NAME} log delivery could not be determined in region {AWS_REGION_US_EAST_1} because the CloudWatch Logs delivery sources could not be listed; verify manually that its application logs are delivered."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            memories=[_memory_summary(MEM_ID, MEM_ARN)],
            sources=[_delivery_source(SOURCE_NAME, [MEM_ARN])],
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
        new=_mock(errors={"ListMemories": "AccessDeniedException"}),
    )
    @mock_aws
    def test_memories_denied_is_manual_not_silence(self):
        """A denied ListMemories must not look like an account with no memories."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "memory/unknown"
        assert "could not be listed" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(errors={"ListMemories": "ValidationException"}),
    )
    @mock_aws
    def test_region_not_supported(self):
        """AgentCore absent from the Region is a definite "no memories"."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            memories=[_memory_summary(MEM_ID, MEM_ARN)],
            sources=[],
            deliveries=[],
            errors={"GetMemory": "AccessDeniedException"},
        ),
    )
    @mock_aws
    def test_denied_get_memory_still_answers_from_the_listing(self):
        """A denied GetMemory costs the name, not the answer.

        The join runs on the ARN from ListMemories, so the delivery state is
        still definite; only the label falls back to the memory id.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert MEM_ID in result[0].status_extended
        assert MEM_NAME not in result[0].status_extended.replace(MEM_ID, "")

    def test_collector_runs_when_only_this_check_is_in_scope(self):
        """This check must switch the delivery collectors on by itself.

        Left out of the gate, both inventories stay empty, every memory reads as
        unknown and the check reports MANUAL against a whole account.
        """
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        calls = []
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_US_EAST_1], expected_checks=[CHECK_NAME]
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

        assert "DescribeDeliverySources" in calls
        assert "DescribeDeliveries" in calls
        assert logs.delivery_sources[AWS_REGION_US_EAST_1] == []
        assert logs.deliveries[AWS_REGION_US_EAST_1] == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            memories=[
                _memory_summary(MEM_ID, MEM_ARN),
                _memory_summary(OTHER_MEM_ID, OTHER_MEM_ARN),
            ],
            sources=[_delivery_source(SOURCE_NAME, [MEM_ARN])],
            deliveries=[_delivery(SOURCE_NAME)],
        ),
    )
    @mock_aws
    def test_multiple_memories_split(self):
        """Two memories yield two findings: only the delivered one PASSes."""
        result = self._run()
        assert len(result) == 2
        by_arn = {report.resource_arn: report for report in result}
        assert set(by_arn) == {MEM_ARN, OTHER_MEM_ARN}
        assert by_arn[MEM_ARN].status == "PASS"
        assert by_arn[OTHER_MEM_ARN].status == "FAIL"
        assert [report.status for report in result].count("PASS") == 1
        assert [report.status for report in result].count("FAIL") == 1
        assert OTHER_MEM_NAME in by_arn[OTHER_MEM_ARN].status_extended
