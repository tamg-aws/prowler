from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import EndpointConfig
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_endpoint_config = "test-endpoint-config"
endpoint_config_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:endpoint-config/{test_endpoint_config}"

CHECK_MODULE = "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_data_capture_enabled.sagemaker_endpoint_data_capture_enabled"


class Test_sagemaker_endpoint_data_capture_enabled:
    def _run(self, endpoint_configs):
        sagemaker_client = mock.MagicMock()
        sagemaker_client.endpoint_configs = endpoint_configs

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_endpoint_data_capture_enabled.sagemaker_endpoint_data_capture_enabled import (
                sagemaker_endpoint_data_capture_enabled,
            )

            return sagemaker_endpoint_data_capture_enabled().execute()

    @staticmethod
    def _endpoint_config(**kwargs):
        return {
            endpoint_config_arn: EndpointConfig(
                name=test_endpoint_config,
                arn=endpoint_config_arn,
                region=AWS_REGION_EU_WEST_1,
                **kwargs,
            )
        }

    def test_no_endpoint_configs(self):
        assert len(self._run({})) == 0

    def test_data_capture_enabled(self):
        result = self._run(self._endpoint_config(data_capture_enabled=True))
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"SageMaker endpoint configuration {test_endpoint_config} has data capture enabled."
        )
        assert result[0].resource_id == test_endpoint_config
        assert result[0].resource_arn == endpoint_config_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_data_capture_disabled(self):
        result = self._run(self._endpoint_config(data_capture_enabled=False))
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"SageMaker endpoint configuration {test_endpoint_config} does not have data capture enabled."
        )
        assert result[0].resource_id == test_endpoint_config
        assert result[0].resource_arn == endpoint_config_arn

    def test_describe_failed(self):
        result = self._run(self._endpoint_config(data_capture_scan_failed=True))
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"SageMaker endpoint configuration {test_endpoint_config} data capture configuration could not be read; manual review is required."
        )
        assert result[0].resource_id == test_endpoint_config
        assert result[0].resource_arn == endpoint_config_arn

    def test_state_unresolved_is_manual_not_fail(self):
        """An unresolved data capture state must not fall through to its falsy default."""
        result = self._run(self._endpoint_config())
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_describe_failed_takes_precedence_over_a_stale_true(self):
        result = self._run(
            self._endpoint_config(
                data_capture_enabled=True, data_capture_scan_failed=True
            )
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
