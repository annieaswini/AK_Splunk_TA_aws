#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for listing AWS inputs.
"""
import json

import splunk.Intersplunk
import splunksdc.log as logging
from solnlib.splunk_rest_client import get_splunkd_access_info

from splunk_ta_aws.common.ta_aws_common import (  # isort: skip
    load_config,
    make_splunk_endpoint,
    make_splunkd_uri,
)

logger = logging.get_module_logger()


INPUT_PATH_LIST = [
    "splunk_ta_aws_aws_cloudtrail",
    "splunk_ta_aws_aws_config",
    "splunk_ta_aws_aws_config_rule",
    "splunk_ta_aws_aws_s3",
    "splunk_ta_aws_aws_billing",
    "splunk_ta_aws_aws_billing_cur",
    "splunk_ta_aws_aws_cloudwatch",
    "splunk_ta_aws_aws_cloudwatch_logs",
    "splunk_ta_aws_aws_metadata",
    "splunk_ta_aws_aws_inspector",
    "splunk_ta_aws_aws_inspector_v2",
    "splunk_ta_aws_aws_kinesis",
    "splunk_ta_aws_splunk_ta_aws_sqs",
    "splunk_ta_aws_splunk_ta_aws_logs",
    "splunk_ta_aws_aws_sqs_based_s3",
]


def _fetch_all_inputs(session_key, results):
    for input_uri in INPUT_PATH_LIST:
        input_type = input_uri[len("splunk_ta_aws_"):]  # fmt: skip

        splunkd_uri = make_splunkd_uri(*get_splunkd_access_info())
        inputs = load_config(
            make_splunk_endpoint(
                splunkd_uri,
                input_uri,
            ),
            session_key,
            "Input",
        )

        for name, input in inputs.items():  # pylint: disable=redefined-builtin
            results.append(
                {
                    "input_account": _get_value(
                        input, "aws_iam_role", "aws_account", "account"
                    ),
                    "input_name": name,
                    "input_sourcetype": input.get("sourcetype"),
                    "input_type": input_type,
                    "input_region": _normalize_region(
                        _get_value(
                            input,
                            "region",
                            "aws_region",
                            "bucket_region",
                            "sqs_queue_region",
                            "aws_regions",
                            "regions",
                        )
                    ),
                    "input_index": input.get("index"),
                    "input_interval": input.get("interval")
                    or input.get("polling_interval"),
                }
            )


def _get_value(dict_obj, *keys):
    for key in keys:
        if key in dict_obj:
            return dict_obj.get(key)
    return None


def _normalize_region(region_field):
    if region_field and region_field.startswith("[") and region_field.endswith("]"):
        return ",".join(json.loads(region_field))
    return region_field


def main():
    """Main method for list_inputs module."""
    factory = logging.StreamHandlerFactory()
    formatter = logging.ContextualLogFormatter(True)
    logging.RootHandler.setup(factory, formatter)
    logger.setLevel(logging.INFO)

    results = []
    try:
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        session_key = settings["sessionKey"]

        _fetch_all_inputs(session_key, results)
    except Exception:  # pylint: disable=broad-except
        import traceback  # pylint: disable=import-outside-toplevel

        stack = traceback.format_exc()
        logger.error("Error : Traceback: " + str(stack))

    splunk.Intersplunk.outputResults(results)
