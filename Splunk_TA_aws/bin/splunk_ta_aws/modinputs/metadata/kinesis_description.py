#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for Kinesis description of description input
"""
from __future__ import absolute_import

import datetime

import boto3
import splunk_ta_aws.common.ta_aws_consts as tac
import splunksdc.log as logging

from . import description as desc

logger = logging.get_module_logger()

CREDENTIAL_THRESHOLD = datetime.timedelta(minutes=20)


def get_kinesis_conn(config):
    """Returns Kinesis connection."""
    return desc.BotoRetryWrapper(
        boto_client=boto3.client(
            "kinesis",
            region_name=config.get(tac.region),
            aws_access_key_id=config.get(tac.key_id),
            aws_secret_access_key=config.get(tac.secret_key),
            aws_session_token=config.get("aws_session_token"),
        )
    )


@desc.generate_credentials
@desc.decorate
def kinesis_stream(config):
    """Yields Kinesis data stream"""
    kinesis_conn = get_kinesis_conn(config)
    # indicates there is more pages
    has_more_streams = True
    # Is last stream name to be read
    exclusive_start_stream_name = None
    # paginate until has_more_streams is false
    while has_more_streams:
        if exclusive_start_stream_name is None:
            stream_names = kinesis_conn.list_streams()
        else:
            stream_names = kinesis_conn.list_streams(
                ExclusiveStartStreamName=exclusive_start_stream_name
            )
        for name in stream_names.get("StreamNames"):
            output = kinesis_conn.describe_stream_summary(StreamName=name)
            logger.debug("Indexing stream description summary", stream=output)
            yield output.get("StreamDescriptionSummary")
            exclusive_start_stream_name = name
        has_more_streams = stream_names.get("HasMoreStreams")
