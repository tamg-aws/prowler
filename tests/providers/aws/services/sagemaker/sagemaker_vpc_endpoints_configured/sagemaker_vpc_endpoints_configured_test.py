from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    Domain,
    EndpointConfig,
    ModelRegistry,
    MonitoringSchedule,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

SAGEMAKER_SERVICES = [
    f"com.amazonaws.{AWS_REGION_US_EAST_1}.sagemaker.api",
    f"com.amazonaws.{AWS_REGION_US_EAST_1}.sagemaker.runtime",
]
SAGEMAKER_FIPS_SERVICES = [
    f"com.amazonaws.{AWS_REGION_US_EAST_1}.sagemaker.api-fips",
    f"com.amazonaws.{AWS_REGION_US_EAST_1}.sagemaker.runtime-fips",
]

test_domain_id = "d-testdomain123"
test_domain_arn = f"arn:aws:sagemaker:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/{test_domain_id}"

CHECK_MODULE = "prowler.providers.aws.services.sagemaker.sagemaker_vpc_endpoints_configured.sagemaker_vpc_endpoints_configured"


def mocked_sagemaker_client(domains=None, endpoint_configs=None, registries=None):
    """A SageMaker client holding only the collections the check reads."""
    return mock.MagicMock(
        sagemaker_notebook_instances=[],
        sagemaker_models=[],
        sagemaker_training_jobs=[],
        sagemaker_processing_jobs=[],
        sagemaker_transform_jobs=[],
        sagemaker_domains=domains if domains is not None else [],
        endpoint_configs=endpoint_configs if endpoint_configs is not None else {},
        sagemaker_model_registries=registries if registries is not None else [],
        sagemaker_monitoring_schedules=[],
    )


def a_domain(region=AWS_REGION_US_EAST_1):
    return Domain(
        domain_id=test_domain_id,
        name="test-domain",
        region=region,
        arn=test_domain_arn,
    )


class Test_sagemaker_vpc_endpoints_configured:
    def _run(self, aws_provider, sagemaker_client):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            vpc_service = VPC(aws_provider)
            with (
                mock.patch(f"{CHECK_MODULE}.vpc_client", new=vpc_service),
                mock.patch(f"{CHECK_MODULE}.sagemaker_client", new=sagemaker_client),
            ):
                from prowler.providers.aws.services.sagemaker.sagemaker_vpc_endpoints_configured.sagemaker_vpc_endpoints_configured import (
                    sagemaker_vpc_endpoints_configured,
                )

                return sagemaker_vpc_endpoints_configured().execute(), vpc_service

    @mock_aws
    def test_no_vpcs_in_use(self):
        """Unused VPCs are skipped when scan_unused_services is disabled."""
        client("ec2", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )
        result, _ = self._run(aws_provider, mocked_sagemaker_client([a_domain()]))
        assert len(result) == 0

    @mock_aws
    def test_no_sagemaker_resources(self):
        """A region holding no SageMaker AI resource is out of scope."""
        client("ec2", region_name=AWS_REGION_US_EAST_1).describe_vpcs()

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result, _ = self._run(aws_provider, mocked_sagemaker_client())
        assert len(result) == 0

    @mock_aws
    def test_registry_alone_does_not_put_a_region_in_scope(self):
        """Model registry and monitoring schedule records are synthesised per region."""
        client("ec2", region_name=AWS_REGION_US_EAST_1).describe_vpcs()

        sagemaker_client = mocked_sagemaker_client(
            registries=[
                ModelRegistry(
                    name="SageMaker Model Registry",
                    arn=f"arn:aws:sagemaker:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:model-registry/unknown",
                    region=AWS_REGION_US_EAST_1,
                )
            ]
        )
        sagemaker_client.sagemaker_monitoring_schedules = [
            MonitoringSchedule(
                name="SageMaker Monitoring Schedules",
                region=AWS_REGION_US_EAST_1,
                arn=f"arn:aws:sagemaker:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:monitoring-schedule/unknown",
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result, _ = self._run(aws_provider, sagemaker_client)
        assert len(result) == 0

    @mock_aws
    def test_endpoint_config_puts_a_region_in_scope(self):
        """Any real SageMaker AI resource, not just a domain, brings a region into scope."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]

        endpoint_config_arn = f"arn:aws:sagemaker:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint-config/test-endpoint-config"
        sagemaker_client = mocked_sagemaker_client(
            endpoint_configs={
                endpoint_config_arn: EndpointConfig(
                    name="test-endpoint-config",
                    arn=endpoint_config_arn,
                    region=AWS_REGION_US_EAST_1,
                )
            }
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result, _ = self._run(aws_provider, sagemaker_client)
        assert len(result) == 1
        assert result[0].resource_id == vpc_id
        assert result[0].status == "FAIL"

    @mock_aws
    def test_vpc_no_endpoints(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result, _ = self._run(aws_provider, mocked_sagemaker_client([a_domain()]))
        assert len(result) == 1
        assert result[0].resource_id == vpc_id
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"VPC {vpc_id} does not have VPC endpoints for the following SageMaker AI services: SageMaker AI control plane, SageMaker AI runtime (InvokeEndpoint)."
        )
        assert (
            result[0].resource_arn
            == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:vpc/{vpc_id}"
        )

    @mock_aws
    def test_vpc_only_runtime_endpoint(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName=f"com.amazonaws.{AWS_REGION_US_EAST_1}.sagemaker.runtime",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result, _ = self._run(aws_provider, mocked_sagemaker_client([a_domain()]))
        # Default VPC plus the created one.
        assert len(result) == 2
        finding = next(f for f in result if f.resource_id == vpc["VpcId"])
        assert finding.status == "FAIL"
        assert (
            finding.status_extended
            == f"VPC {vpc['VpcId']} does not have VPC endpoints for the following SageMaker AI services: SageMaker AI control plane."
        )

    @mock_aws
    def test_vpc_all_endpoints(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        for service_name in SAGEMAKER_SERVICES:
            ec2_client.create_vpc_endpoint(
                VpcId=vpc["VpcId"],
                ServiceName=service_name,
                RouteTableIds=[route_table["RouteTableId"]],
                VpcEndpointType="Interface",
            )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result, _ = self._run(aws_provider, mocked_sagemaker_client([a_domain()]))
        assert len(result) == 2
        finding = next(f for f in result if f.resource_id == vpc["VpcId"])
        assert finding.status == "PASS"
        assert (
            finding.status_extended
            == f"VPC {vpc['VpcId']} has VPC endpoints for all SageMaker AI services."
        )

    @mock_aws
    def test_fips_endpoints_satisfy_the_check(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        for service_name in SAGEMAKER_FIPS_SERVICES:
            ec2_client.create_vpc_endpoint(
                VpcId=vpc["VpcId"],
                ServiceName=service_name,
                RouteTableIds=[route_table["RouteTableId"]],
                VpcEndpointType="Interface",
            )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result, _ = self._run(aws_provider, mocked_sagemaker_client([a_domain()]))
        finding = next(f for f in result if f.resource_id == vpc["VpcId"])
        assert finding.status == "PASS"

    @mock_aws
    def test_featurestore_endpoint_does_not_satisfy_the_check(self):
        """A different SageMaker AI endpoint service must not be mistaken for these two."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName=f"com.amazonaws.{AWS_REGION_US_EAST_1}.sagemaker.featurestore-runtime",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result, _ = self._run(aws_provider, mocked_sagemaker_client([a_domain()]))
        finding = next(f for f in result if f.resource_id == vpc["VpcId"])
        assert finding.status == "FAIL"
        assert "SageMaker AI control plane" in finding.status_extended
        assert "SageMaker AI runtime (InvokeEndpoint)" in finding.status_extended

    @mock_aws
    def test_pending_endpoint_does_not_count(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        for service_name in SAGEMAKER_SERVICES:
            ec2_client.create_vpc_endpoint(
                VpcId=vpc["VpcId"],
                ServiceName=service_name,
                RouteTableIds=[route_table["RouteTableId"]],
                VpcEndpointType="Interface",
            )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        sagemaker_client = mocked_sagemaker_client([a_domain()])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            vpc_service = VPC(aws_provider)
            for endpoint in vpc_service.vpc_endpoints:
                if endpoint.vpc_id == vpc["VpcId"]:
                    endpoint.state = "pending"
            with (
                mock.patch(f"{CHECK_MODULE}.vpc_client", new=vpc_service),
                mock.patch(f"{CHECK_MODULE}.sagemaker_client", new=sagemaker_client),
            ):
                from prowler.providers.aws.services.sagemaker.sagemaker_vpc_endpoints_configured.sagemaker_vpc_endpoints_configured import (
                    sagemaker_vpc_endpoints_configured,
                )

                result = sagemaker_vpc_endpoints_configured().execute()

        finding = next(f for f in result if f.resource_id == vpc["VpcId"])
        assert finding.status == "FAIL"

    @mock_aws
    def test_gateway_endpoint_does_not_count(self):
        """Only interface endpoints carry the SageMaker AI APIs over PrivateLink."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        for service_name in SAGEMAKER_SERVICES:
            ec2_client.create_vpc_endpoint(
                VpcId=vpc["VpcId"],
                ServiceName=service_name,
                RouteTableIds=[route_table["RouteTableId"]],
                VpcEndpointType="Interface",
            )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        sagemaker_client = mocked_sagemaker_client([a_domain()])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            vpc_service = VPC(aws_provider)
            for endpoint in vpc_service.vpc_endpoints:
                if endpoint.vpc_id == vpc["VpcId"]:
                    endpoint.type = "Gateway"
            with (
                mock.patch(f"{CHECK_MODULE}.vpc_client", new=vpc_service),
                mock.patch(f"{CHECK_MODULE}.sagemaker_client", new=sagemaker_client),
            ):
                from prowler.providers.aws.services.sagemaker.sagemaker_vpc_endpoints_configured.sagemaker_vpc_endpoints_configured import (
                    sagemaker_vpc_endpoints_configured,
                )

                result = sagemaker_vpc_endpoints_configured().execute()

        finding = next(f for f in result if f.resource_id == vpc["VpcId"])
        assert finding.status == "FAIL"

    @mock_aws
    def test_endpoint_in_another_vpc_does_not_count(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_with_endpoints = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        vpc_without = ec2_client.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]
        route_table = ec2_client.create_route_table(VpcId=vpc_with_endpoints["VpcId"])[
            "RouteTable"
        ]
        for service_name in SAGEMAKER_SERVICES:
            ec2_client.create_vpc_endpoint(
                VpcId=vpc_with_endpoints["VpcId"],
                ServiceName=service_name,
                RouteTableIds=[route_table["RouteTableId"]],
                VpcEndpointType="Interface",
            )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result, _ = self._run(aws_provider, mocked_sagemaker_client([a_domain()]))
        assert (
            next(
                f for f in result if f.resource_id == vpc_with_endpoints["VpcId"]
            ).status
            == "PASS"
        )
        assert (
            next(f for f in result if f.resource_id == vpc_without["VpcId"]).status
            == "FAIL"
        )
