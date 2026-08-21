from unittest.mock import MagicMock, patch
from uuid import uuid4

import botocore

from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    Model,
    SageMaker,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_model_package_group_name = "test-model-package-group"
test_model_package_group_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:model-package-group/{test_model_package_group_name}"
test_model_package_name = "test-model-package"
test_model_package_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:model-package/{test_model_package_name}/1"

test_notebook_instance = "test-notebook-instance"
notebook_instance_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:notebook-instance/{test_notebook_instance}"
test_model = "test-model"
test_arn_model = (
    f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:model/{test_model}"
)
test_training_job = "test-training-job"
test_arn_training_job = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:training-job/{test_model}"
# Two transform jobs on two ListTransformJobs pages, so a first-page-only
# collector fails the pagination test below.
test_transform_job_page_1 = "test-transform-job-page-1"
test_transform_job_page_2 = "test-transform-job-page-2"
test_arn_transform_job_page_1 = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:transform-job/{test_transform_job_page_1}"
test_arn_transform_job_page_2 = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:transform-job/{test_transform_job_page_2}"
transform_jobs_next_token = "transform-jobs-page-2"
# Page-two fixtures for the collectors the shared mock keeps at one entry, so their
# pagination is proven without disturbing the single-resource assertions elsewhere.
test_training_job_page_2 = "test-training-job-page-2"
test_arn_training_job_page_2 = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:training-job/{test_training_job_page_2}"
training_jobs_next_token = "training-jobs-page-2"
endpoint_config_name_page_2 = "endpoint-config-test-page-2"
endpoint_config_arn_page_2 = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:endpoint-config/{endpoint_config_name_page_2}"
endpoint_configs_next_token = "endpoint-configs-page-2"
subnet_id = "subnet-" + str(uuid4())
kms_key_id = str(uuid4())
output_kms_key_id = str(uuid4())
transform_output_kms_key_id = str(uuid4())
transform_volume_kms_key_id = str(uuid4())
lifecycle_config_name = "test-lifecycle-config"
# base64 of "echo OnCreate" / "echo OnStart"
lifecycle_on_create_b64 = "ZWNobyBPbkNyZWF0ZQ=="
lifecycle_on_start_b64 = "ZWNobyBPblN0YXJ0"
endpoint_config_name = "endpoint-config-test"
endpoint_config_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:endpoint-config/{endpoint_config_name}"
prod_variant_name = "Variant1"
test_domain_name = "test-domain"
test_domain_id = "d-testdomain123"
test_domain_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:domain/{test_domain_id}"
test_sso_instance_id = "app-test-instance-id"
test_sso_application_arn = (
    f"arn:aws:sso::{AWS_ACCOUNT_NUMBER}:application/sagemaker/apl-test"
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListNotebookInstances":
        return {
            "NotebookInstances": [
                {
                    "NotebookInstanceName": test_notebook_instance,
                    "NotebookInstanceArn": notebook_instance_arn,
                },
            ]
        }
    if operation_name == "ListModels":
        return {
            "Models": [
                {
                    "ModelName": test_model,
                    "ModelArn": test_arn_model,
                },
            ]
        }
    if operation_name == "ListTrainingJobs":
        return {
            "TrainingJobSummaries": [
                {
                    "TrainingJobName": test_training_job,
                    "TrainingJobArn": test_arn_training_job,
                },
            ]
        }
    if operation_name == "ListTransformJobs":
        if kwarg.get("NextToken") == transform_jobs_next_token:
            return {
                "TransformJobSummaries": [
                    {
                        "TransformJobName": test_transform_job_page_2,
                        "TransformJobArn": test_arn_transform_job_page_2,
                    },
                ]
            }
        return {
            "TransformJobSummaries": [
                {
                    "TransformJobName": test_transform_job_page_1,
                    "TransformJobArn": test_arn_transform_job_page_1,
                },
            ],
            "NextToken": transform_jobs_next_token,
        }
    if operation_name == "DescribeTransformJob":
        return {
            "TransformJobName": kwarg["TransformJobName"],
            "TransformOutput": {
                "S3OutputPath": "s3://test-bucket/output/",
                "KmsKeyId": transform_output_kms_key_id,
            },
            "TransformResources": {
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeKmsKeyId": transform_volume_kms_key_id,
            },
        }
    if operation_name == "DescribeNotebookInstance":
        return {
            "SubnetId": subnet_id,
            "KmsKeyId": kms_key_id,
            "DirectInternetAccess": "Enabled",
            "RootAccess": "Enabled",
            "NotebookInstanceLifecycleConfigName": lifecycle_config_name,
        }
    if operation_name == "DescribeNotebookInstanceLifecycleConfig":
        return {
            "OnCreate": [{"Content": lifecycle_on_create_b64}],
            "OnStart": [{"Content": lifecycle_on_start_b64}],
        }
    if operation_name == "DescribeModel":
        return {
            "VpcConfig": {
                "Subnets": [
                    subnet_id,
                ]
            },
            "EnableNetworkIsolation": True,
        }
    if operation_name == "DescribeTrainingJob":
        return {
            "ResourceConfig": {
                "VolumeKmsKeyId": kms_key_id,
            },
            "OutputDataConfig": {
                "S3OutputPath": "s3://test-bucket/output/",
                "KmsKeyId": output_kms_key_id,
            },
            "VpcConfig": {
                "Subnets": [
                    subnet_id,
                ]
            },
            "EnableNetworkIsolation": True,
            "EnableInterContainerTrafficEncryption": True,
        }
    if operation_name == "ListModelPackageGroups":
        return {
            "ModelPackageGroupSummaryList": [
                {
                    "ModelPackageGroupName": test_model_package_group_name,
                    "ModelPackageGroupArn": test_model_package_group_arn,
                },
            ]
        }
    if operation_name == "ListModelPackages":
        return {
            "ModelPackageSummaryList": [
                {
                    "ModelPackageName": test_model_package_name,
                    "ModelPackageArn": test_model_package_arn,
                    "ModelApprovalStatus": "Approved",
                },
            ]
        }
    if operation_name == "ListTags":
        return {
            "Tags": [
                {"Key": "test", "Value": "test"},
            ],
        }
    if operation_name == "ListEndpointConfigs":
        return {
            "EndpointConfigs": [
                {
                    "EndpointConfigName": endpoint_config_name,
                    "EndpointConfigArn": endpoint_config_arn,
                },
            ],
        }
    if operation_name == "DescribeEndpointConfig":
        return {
            "ProductionVariants": [
                {
                    "VariantName": prod_variant_name,
                    "InitialInstanceCount": 5,
                },
                {
                    "VariantName": "Variant2",
                    "InitialInstanceCount": 2,
                },
            ],
            "DataCaptureConfig": {
                "EnableCapture": True,
                "InitialSamplingPercentage": 100,
                "DestinationS3Uri": "s3://test-bucket/datacapture/",
                "CaptureOptions": [{"CaptureMode": "InputAndOutput"}],
            },
        }
    if operation_name == "ListDomains":
        return {
            "Domains": [
                {
                    "DomainId": test_domain_id,
                    "DomainName": test_domain_name,
                    "DomainArn": test_domain_arn,
                },
            ],
        }
    if operation_name == "DescribeDomain":
        return {
            "DomainId": test_domain_id,
            "DomainName": test_domain_name,
            "DomainArn": test_domain_arn,
            "AuthMode": "SSO",
            "SingleSignOnManagedApplicationInstanceId": test_sso_instance_id,
            "SingleSignOnApplicationArn": test_sso_application_arn,
        }

    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_SageMaker_Service:
    # Test SageMaker Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert sagemaker.service == "sagemaker"

    # Test SageMaker client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        for reg_client in sagemaker.regional_clients.values():
            assert reg_client.__class__.__name__ == "SageMaker"

    # Test SageMaker session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert sagemaker.session.__class__.__name__ == "Session"

    # Test SageMaker list notebook instances
    def test_list_notebook_instances(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_notebook_instances) == 1
        assert sagemaker.sagemaker_notebook_instances[0].name == test_notebook_instance
        assert sagemaker.sagemaker_notebook_instances[0].arn == notebook_instance_arn
        assert sagemaker.sagemaker_notebook_instances[0].region == AWS_REGION_EU_WEST_1
        assert sagemaker.sagemaker_notebook_instances[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test SageMaker list models
    def test_list_models(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_models) == 1
        assert sagemaker.sagemaker_models[0].name == test_model
        assert sagemaker.sagemaker_models[0].arn == test_arn_model
        assert sagemaker.sagemaker_models[0].region == AWS_REGION_EU_WEST_1
        assert sagemaker.sagemaker_models[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test SageMaker list training jobs
    def test_list_training_jobs(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_training_jobs) == 1
        assert sagemaker.sagemaker_training_jobs[0].name == test_training_job
        assert sagemaker.sagemaker_training_jobs[0].arn == test_arn_training_job
        assert sagemaker.sagemaker_training_jobs[0].region == AWS_REGION_EU_WEST_1
        assert sagemaker.sagemaker_training_jobs[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test SageMaker describe notebook instance
    def test_describe_notebook_instance(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_notebook_instances) == 1
        assert sagemaker.sagemaker_notebook_instances[0].root_access
        assert sagemaker.sagemaker_notebook_instances[0].subnet_id == subnet_id
        assert sagemaker.sagemaker_notebook_instances[0].direct_internet_access
        assert sagemaker.sagemaker_notebook_instances[0].kms_key_id == kms_key_id
        assert (
            sagemaker.sagemaker_notebook_instances[0].lifecycle_config_name
            == lifecycle_config_name
        )

    def test_describe_notebook_instance_direct_internet_independent_of_root_access(
        self,
    ):
        """DirectInternetAccess and RootAccess are separate settings and must be read separately.

        The shared fixture sets both to "Enabled", so a collector that reads RootAccess while
        testing for the DirectInternetAccess key produces the right answer by coincidence. These
        two cases separate the fields, which is the only way the confusion is visible.
        """

        def only_direct_internet(self, operation_name, kwarg):
            if operation_name == "DescribeNotebookInstance":
                return {"DirectInternetAccess": "Enabled", "RootAccess": "Disabled"}
            return mock_make_api_call(self, operation_name, kwarg)

        def only_root_access(self, operation_name, kwarg):
            if operation_name == "DescribeNotebookInstance":
                return {"DirectInternetAccess": "Disabled", "RootAccess": "Enabled"}
            return mock_make_api_call(self, operation_name, kwarg)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with patch(
            "botocore.client.BaseClient._make_api_call", new=only_direct_internet
        ):
            notebook = SageMaker(aws_provider).sagemaker_notebook_instances[0]
            assert notebook.direct_internet_access
            assert not notebook.root_access

        with patch("botocore.client.BaseClient._make_api_call", new=only_root_access):
            notebook = SageMaker(aws_provider).sagemaker_notebook_instances[0]
            assert not notebook.direct_internet_access
            assert notebook.root_access

    # Test SageMaker describe notebook instance lifecycle config
    def test_describe_notebook_instance_lifecycle_config(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        notebook_instance = sagemaker.sagemaker_notebook_instances[0]
        assert notebook_instance.lifecycle_scan_failed is False
        assert notebook_instance.lifecycle_scripts == {
            "OnCreate[0]": "echo OnCreate",
            "OnStart[0]": "echo OnStart",
        }

    # Test SageMaker describe model
    def test_describe_model(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_models) == 1
        assert sagemaker.sagemaker_models[0].network_isolation
        assert sagemaker.sagemaker_models[0].vpc_config_subnets == [subnet_id]

    # Test SageMaker describe training jobs
    def test_describe_training_jobs(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_training_jobs) == 1
        assert sagemaker.sagemaker_training_jobs[0].container_traffic_encryption
        assert sagemaker.sagemaker_training_jobs[0].network_isolation
        assert sagemaker.sagemaker_training_jobs[0].volume_kms_key_id == kms_key_id
        assert sagemaker.sagemaker_training_jobs[0].vpc_config_subnets == [subnet_id]

    # Test SageMaker describe training jobs output data config
    def test_describe_training_jobs_output_data_config(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        training_job = sagemaker.sagemaker_training_jobs[0]
        assert training_job.output_kms_key_id == output_kms_key_id
        assert training_job.output_config_scan_failed is False

    def test_describe_training_jobs_without_output_data_config(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_without_output_data_config(self, operation_name, kwarg):
            if operation_name == "DescribeTrainingJob":
                return {"ResourceConfig": {"VolumeKmsKeyId": kms_key_id}}
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_without_output_data_config,
        ):
            sagemaker = SageMaker(aws_provider)
            training_job = sagemaker.sagemaker_training_jobs[0]
            assert training_job.output_kms_key_id is None
            assert training_job.output_config_scan_failed is True

    def test_describe_training_jobs_describe_error(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_describe_error(self, operation_name, kwarg):
            if operation_name == "DescribeTrainingJob":
                raise botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "User is not authorized to perform sagemaker:DescribeTrainingJob",
                        }
                    },
                    "DescribeTrainingJob",
                )
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_describe_error
        ):
            sagemaker = SageMaker(aws_provider)
            training_job = sagemaker.sagemaker_training_jobs[0]
            assert training_job.output_kms_key_id is None
            assert training_job.output_config_scan_failed is True

    def test_list_training_jobs_paginates(self):
        """The output encryption check under-reports if this reads page one only."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_two_pages(self, operation_name, kwarg):
            if operation_name == "ListTrainingJobs":
                if kwarg.get("NextToken") == training_jobs_next_token:
                    return {
                        "TrainingJobSummaries": [
                            {
                                "TrainingJobName": test_training_job_page_2,
                                "TrainingJobArn": test_arn_training_job_page_2,
                            },
                        ]
                    }
                return {
                    "TrainingJobSummaries": [
                        {
                            "TrainingJobName": test_training_job,
                            "TrainingJobArn": test_arn_training_job,
                        },
                    ],
                    "NextToken": training_jobs_next_token,
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_two_pages):
            sagemaker = SageMaker(aws_provider)
            names = sorted(job.name for job in sagemaker.sagemaker_training_jobs)
            arns = sorted(job.arn for job in sagemaker.sagemaker_training_jobs)
            assert names == sorted([test_training_job, test_training_job_page_2])
            assert arns == sorted([test_arn_training_job, test_arn_training_job_page_2])

    def test_list_endpoint_configs_paginates(self):
        """The data capture check under-reports if this reads page one only."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_two_pages(self, operation_name, kwarg):
            if operation_name == "ListEndpointConfigs":
                if kwarg.get("NextToken") == endpoint_configs_next_token:
                    return {
                        "EndpointConfigs": [
                            {
                                "EndpointConfigName": endpoint_config_name_page_2,
                                "EndpointConfigArn": endpoint_config_arn_page_2,
                            },
                        ]
                    }
                return {
                    "EndpointConfigs": [
                        {
                            "EndpointConfigName": endpoint_config_name,
                            "EndpointConfigArn": endpoint_config_arn,
                        },
                    ],
                    "NextToken": endpoint_configs_next_token,
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_two_pages):
            sagemaker = SageMaker(aws_provider)
            assert sorted(sagemaker.endpoint_configs) == sorted(
                [endpoint_config_arn, endpoint_config_arn_page_2]
            )
            assert (
                sagemaker.endpoint_configs[endpoint_config_arn_page_2].name
                == endpoint_config_name_page_2
            )
            assert (
                sagemaker.endpoint_configs[
                    endpoint_config_arn_page_2
                ].data_capture_enabled
                is True
            )

    # Test SageMaker list transform jobs
    def test_list_transform_jobs_paginates(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        names = [job.name for job in sagemaker.sagemaker_transform_jobs]
        arns = [job.arn for job in sagemaker.sagemaker_transform_jobs]
        # The second entry only exists on page two of ListTransformJobs.
        assert sorted(names) == [test_transform_job_page_1, test_transform_job_page_2]
        assert sorted(arns) == sorted(
            [test_arn_transform_job_page_1, test_arn_transform_job_page_2]
        )
        for job in sagemaker.sagemaker_transform_jobs:
            assert job.region == AWS_REGION_EU_WEST_1
            assert job.tags == [{"Key": "test", "Value": "test"}]

    # Test SageMaker describe transform job
    def test_describe_transform_job(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        for job in sagemaker.sagemaker_transform_jobs:
            assert job.instance_type == "ml.m5.large"
            assert job.volume_kms_key_id == transform_volume_kms_key_id
            assert job.output_kms_key_id == transform_output_kms_key_id
            assert job.encryption_config_scan_failed is False

    def test_describe_transform_job_without_instance_type(self):
        """InstanceType is a required member; without it the volume clause is undecidable."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_without_instance_type(self, operation_name, kwarg):
            if operation_name == "DescribeTransformJob":
                return {
                    "TransformJobName": kwarg["TransformJobName"],
                    "TransformOutput": {
                        "S3OutputPath": "s3://test-bucket/output/",
                        "KmsKeyId": transform_output_kms_key_id,
                    },
                    "TransformResources": {"InstanceCount": 1},
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_without_instance_type
        ):
            sagemaker = SageMaker(aws_provider)
            for job in sagemaker.sagemaker_transform_jobs:
                assert job.instance_type is None
                assert job.encryption_config_scan_failed is True

    def test_describe_transform_job_local_storage_instance(self):
        """A local-storage instance legitimately reports no VolumeKmsKeyId."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_local_storage(self, operation_name, kwarg):
            if operation_name == "DescribeTransformJob":
                return {
                    "TransformJobName": kwarg["TransformJobName"],
                    "TransformOutput": {
                        "S3OutputPath": "s3://test-bucket/output/",
                        "KmsKeyId": transform_output_kms_key_id,
                    },
                    "TransformResources": {
                        "InstanceType": "ml.g5.2xlarge",
                        "InstanceCount": 1,
                    },
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_local_storage):
            sagemaker = SageMaker(aws_provider)
            for job in sagemaker.sagemaker_transform_jobs:
                assert job.instance_type == "ml.g5.2xlarge"
                assert job.volume_kms_key_id is None
                assert job.encryption_config_scan_failed is False

    def test_describe_transform_job_without_transform_output(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_without_transform_output(self, operation_name, kwarg):
            if operation_name == "DescribeTransformJob":
                return {
                    "TransformJobName": kwarg["TransformJobName"],
                    "TransformResources": {
                        "InstanceType": "ml.m5.large",
                        "InstanceCount": 1,
                        "VolumeKmsKeyId": transform_volume_kms_key_id,
                    },
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_without_transform_output,
        ):
            sagemaker = SageMaker(aws_provider)
            for job in sagemaker.sagemaker_transform_jobs:
                assert job.output_kms_key_id is None
                assert job.encryption_config_scan_failed is True

    def test_describe_transform_job_without_transform_resources(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_without_transform_resources(self, operation_name, kwarg):
            if operation_name == "DescribeTransformJob":
                return {
                    "TransformJobName": kwarg["TransformJobName"],
                    "TransformOutput": {
                        "S3OutputPath": "s3://test-bucket/output/",
                        "KmsKeyId": transform_output_kms_key_id,
                    },
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_without_transform_resources,
        ):
            sagemaker = SageMaker(aws_provider)
            for job in sagemaker.sagemaker_transform_jobs:
                assert job.volume_kms_key_id is None
                assert job.encryption_config_scan_failed is True

    def test_describe_transform_job_without_either_kms_key(self):
        """Both structures present but neither carries a key: a definite FAIL, not MANUAL."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_without_keys(self, operation_name, kwarg):
            if operation_name == "DescribeTransformJob":
                return {
                    "TransformJobName": kwarg["TransformJobName"],
                    "TransformOutput": {"S3OutputPath": "s3://test-bucket/output/"},
                    "TransformResources": {
                        "InstanceType": "ml.m5.large",
                        "InstanceCount": 1,
                    },
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_without_keys):
            sagemaker = SageMaker(aws_provider)
            for job in sagemaker.sagemaker_transform_jobs:
                assert job.volume_kms_key_id is None
                assert job.output_kms_key_id is None
                assert job.encryption_config_scan_failed is False

    def test_describe_transform_job_describe_error(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_describe_error(self, operation_name, kwarg):
            if operation_name == "DescribeTransformJob":
                raise botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "User is not authorized to perform sagemaker:DescribeTransformJob",
                        }
                    },
                    "DescribeTransformJob",
                )
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_describe_error
        ):
            sagemaker = SageMaker(aws_provider)
            for job in sagemaker.sagemaker_transform_jobs:
                assert job.volume_kms_key_id is None
                assert job.output_kms_key_id is None
                assert job.encryption_config_scan_failed is True

    # Test SageMaker list endpoint configs
    def test_list_endpoint_configs(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.endpoint_configs) == 1
        assert (
            sagemaker.endpoint_configs[endpoint_config_arn].name == endpoint_config_name
        )
        assert (
            sagemaker.endpoint_configs[endpoint_config_arn].arn == endpoint_config_arn
        )
        assert (
            sagemaker.endpoint_configs[endpoint_config_arn].region
            == AWS_REGION_EU_WEST_1
        )
        assert sagemaker.sagemaker_notebook_instances[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test SageMaker describe training jobs
    def test_describe_endpoint_configs(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.endpoint_configs) == 1
        assert sagemaker.endpoint_configs[endpoint_config_arn].production_variants
        for prod_variant in sagemaker.endpoint_configs[
            endpoint_config_arn
        ].production_variants:
            if prod_variant.name == prod_variant_name:
                assert prod_variant.initial_instance_count == 5
            else:
                assert prod_variant.initial_instance_count == 2

    # Test SageMaker describe endpoint config data capture
    def test_describe_endpoint_configs_data_capture(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        endpoint_config = sagemaker.endpoint_configs[endpoint_config_arn]
        assert endpoint_config.data_capture_enabled is True
        assert endpoint_config.data_capture_scan_failed is False

    def test_describe_endpoint_configs_data_capture_disabled(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_capture_disabled(self, operation_name, kwarg):
            if operation_name == "DescribeEndpointConfig":
                return {
                    "ProductionVariants": [
                        {"VariantName": prod_variant_name, "InitialInstanceCount": 5},
                    ],
                    "DataCaptureConfig": {
                        "EnableCapture": False,
                        "InitialSamplingPercentage": 100,
                        "DestinationS3Uri": "s3://test-bucket/datacapture/",
                        "CaptureOptions": [{"CaptureMode": "InputAndOutput"}],
                    },
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_capture_disabled
        ):
            sagemaker = SageMaker(aws_provider)
            endpoint_config = sagemaker.endpoint_configs[endpoint_config_arn]
            assert endpoint_config.data_capture_enabled is False
            assert endpoint_config.data_capture_scan_failed is False

    def test_describe_endpoint_configs_without_data_capture_config(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_without_data_capture(self, operation_name, kwarg):
            if operation_name == "DescribeEndpointConfig":
                return {
                    "ProductionVariants": [
                        {"VariantName": prod_variant_name, "InitialInstanceCount": 5},
                    ],
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_without_data_capture
        ):
            sagemaker = SageMaker(aws_provider)
            endpoint_config = sagemaker.endpoint_configs[endpoint_config_arn]
            assert endpoint_config.data_capture_enabled is False
            assert endpoint_config.data_capture_scan_failed is False

    def test_describe_endpoint_configs_data_capture_defaults_enabled(self):
        """DataCaptureConfig without EnableCapture: the API documents it as enabled."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_capture_without_flag(self, operation_name, kwarg):
            if operation_name == "DescribeEndpointConfig":
                return {
                    "ProductionVariants": [
                        {"VariantName": prod_variant_name, "InitialInstanceCount": 5},
                    ],
                    "DataCaptureConfig": {
                        "InitialSamplingPercentage": 100,
                        "DestinationS3Uri": "s3://test-bucket/datacapture/",
                        "CaptureOptions": [{"CaptureMode": "InputAndOutput"}],
                    },
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_capture_without_flag
        ):
            sagemaker = SageMaker(aws_provider)
            endpoint_config = sagemaker.endpoint_configs[endpoint_config_arn]
            assert endpoint_config.data_capture_enabled is True
            assert endpoint_config.data_capture_scan_failed is False

    def test_describe_endpoint_configs_describe_error(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_describe_error(self, operation_name, kwarg):
            if operation_name == "DescribeEndpointConfig":
                raise botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "User is not authorized to perform sagemaker:DescribeEndpointConfig",
                        }
                    },
                    "DescribeEndpointConfig",
                )
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_describe_error
        ):
            sagemaker = SageMaker(aws_provider)
            endpoint_config = sagemaker.endpoint_configs[endpoint_config_arn]
            assert endpoint_config.data_capture_enabled is None
            assert endpoint_config.data_capture_scan_failed is True

    # Test SageMaker list domains
    def test_list_domains(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_domains) == 1
        assert sagemaker.sagemaker_domains[0].domain_id == test_domain_id
        assert sagemaker.sagemaker_domains[0].name == test_domain_name
        assert sagemaker.sagemaker_domains[0].arn == test_domain_arn
        assert sagemaker.sagemaker_domains[0].region == AWS_REGION_EU_WEST_1

    # Test SageMaker describe domain
    def test_describe_domain(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_domains) == 1
        assert sagemaker.sagemaker_domains[0].auth_mode == "SSO"
        assert (
            sagemaker.sagemaker_domains[
                0
            ].single_sign_on_managed_application_instance_id
            == test_sso_instance_id
        )
        assert (
            sagemaker.sagemaker_domains[0].single_sign_on_application_arn
            == test_sso_application_arn
        )

    # Test SageMaker _list_tags_for_resource
    def test_list_tags_for_resource_calls_client(self):
        """Test that _list_tags_for_resource calls the correct AWS client and updates the resource."""
        # Mock audit info
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = AWS_ACCOUNT_NUMBER
        audit_info.audit_resources = None

        # Mock regional client
        regional_client = MagicMock()
        regional_client.region = AWS_REGION_EU_WEST_1
        regional_client.list_tags.return_value = {
            "Tags": [{"Key": "foo", "Value": "bar"}]
        }

        # Create service instance (mocking init to avoid full setup)
        with patch.object(SageMaker, "__init__", return_value=None):
            sagemaker_service = SageMaker(audit_info)
            sagemaker_service.regional_clients = {AWS_REGION_EU_WEST_1: regional_client}
            sagemaker_service.audit_info = audit_info

        # Create a mock resource
        resource = Model(
            name="test-model",
            region=AWS_REGION_EU_WEST_1,
            arn=f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:model/test-model",
        )

        # Execute method under test
        sagemaker_service._list_tags_for_resource(resource)

        # Verification
        regional_client.list_tags.assert_called_once_with(ResourceArn=resource.arn)
        assert len(resource.tags) == 1
        assert resource.tags[0]["Key"] == "foo"
        assert resource.tags[0]["Value"] == "bar"

    # Test SageMaker parallel tag listing
    def test_init_calls_threading_for_tags(self):
        """Test that __init__ calls __threading_call__ for tag listing for each resource type."""
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = AWS_ACCOUNT_NUMBER

        # We mock __threading_call__ to verify it is called with the right arguments
        with patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker.__threading_call__"
        ) as mock_threading_call:
            # We also need to mock the other methods called in init to avoid errors
            with (
                patch(
                    "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_notebook_instances"
                ),
                patch(
                    "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_models"
                ),
                patch(
                    "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_training_jobs"
                ),
                patch(
                    "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_transform_jobs"
                ),
                patch(
                    "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_endpoint_configs"
                ),
                patch(
                    "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_domains"
                ),
            ):
                sagemaker_service = SageMaker(audit_info)

                # Check that __threading_call__ was called for _list_tags_for_resource
                # (one for each resource type: models, notebooks, training jobs, processing jobs, transform jobs, endpoint configs, domains)
                tag_calls = [
                    c
                    for c in mock_threading_call.call_args_list
                    if c[0][0] == sagemaker_service._list_tags_for_resource
                ]
                assert len(tag_calls) == 7

    # Test SageMaker list model package groups
    def test_list_model_package_groups(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_model_registries) == 1
        registry = sagemaker.sagemaker_model_registries[0]
        assert registry.region == AWS_REGION_EU_WEST_1
        assert registry.has_groups is True
        assert registry.has_approved_packages is True

    def test_list_model_package_groups_access_denied(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        def mock_access_denied(self, operation_name, kwarg):
            if operation_name == "ListModelPackageGroups":
                raise botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "User is not authorized to perform sagemaker:ListModelPackageGroups",
                        }
                    },
                    "ListModelPackageGroups",
                )
            return make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_access_denied):
            sagemaker = SageMaker(aws_provider)
            assert sagemaker.sagemaker_model_registries == []
