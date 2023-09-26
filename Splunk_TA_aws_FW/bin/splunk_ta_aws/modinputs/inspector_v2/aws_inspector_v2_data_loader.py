#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for AWS inspector v2 data loader.
"""
from __future__ import absolute_import

import datetime
import math
import threading
import time
import traceback
from operator import le  # noqa: F401 # pylint: disable=unused-import

import splunk_ta_aws.common.ta_aws_common as tacommon
import splunk_ta_aws.common.ta_aws_consts as tac
from botocore.exceptions import ClientError
from six.moves import range  # noqa: F401 # pylint: disable=unused-import
from splunksdc import log as logging
from splunktalib import state_store

BUFFER_TIME = 120  # keeping buffer for end-date filter
START_TIME = 1  # keeping 1 sec extra for Iclusive date-time filter

logger = logging.get_module_logger()


class AWSInspectorV2FindingsDataLoader:  # pylint: disable=too-many-instance-attributes
    """Class for AWS inspector v2 findings data loader."""

    def __init__(self, config, client, account_id):
        self._cli = client
        self._state_store = state_store.get_state_store(
            config,
            config[tac.app_name],
            collection_name="aws_inspector_v2",
            use_kv_store=config.get(tac.use_kv_store),
        )
        self._config = config

        self._last_check_at = 0
        self.region = config[tac.region]
        data_input = config[tac.datainput]
        self._source = "{}:{}:inspector:v2:finding".format(  # pylint: disable=consider-using-f-string
            account_id, self.region
        )
        self._source_type = self._config.get(
            tac.sourcetype, "aws:inspector:v2:findings"
        )
        self._state_key = tacommon.b64encode_text(
            "findings_v2_{}_{}".format(  # pylint: disable=consider-using-f-string
                data_input, self.region
            )
        )

    @property
    def _writer(self):
        return self._config[tac.event_writer]

    def run(self):
        """Run method for input"""
        self._load()
        end = int(time.time()) - BUFFER_TIME
        begin = self._last_check_at + START_TIME  # adding 1 sec
        time_start = time.perf_counter()
        self._get_findings(begin, end)
        time_stop = time.perf_counter()
        total_time_elapsed = time_stop - time_start
        logger.info(
            "Time Elapsed(seconds) - total time during pagination: %s",
            total_time_elapsed,
        )

    def _get_findings(self, begin, end):
        # boto3 do not accept unix timestamp on windows
        # cast to datetime by hand
        begin = datetime.datetime.utcfromtimestamp(begin)
        end = datetime.datetime.utcfromtimestamp(end)
        params = {
            "filterCriteria": {
                "lastObservedAt": [{"startInclusive": begin, "endInclusive": end}]
            },
            "sortCriteria": {"field": "LAST_OBSERVED_AT", "sortOrder": "ASC"},
        }
        logger.debug("params: %s", params)
        paginator = self._cli.get_paginator("list_findings")
        total_findings = 0
        try:
            for page in paginator.paginate(**params):
                for finding in page.get("findings", []):
                    total_findings += 1
                    etime = tacommon.total_seconds(finding["lastObservedAt"])
                    event = self._writer.create_event(
                        index=self._config.get(tac.index, "default"),
                        host=self._config.get(tac.host, ""),
                        source=self._source,
                        sourcetype=self._source_type,
                        time=None,
                        unbroken=False,
                        done=False,
                        events=finding,
                    )
                    self._writer.write_events((event,))
                    self._last_check_at = etime
        except ClientError as ce:  # pylint: disable=invalid-name
            logger.error("Failed to collect data, Exception: %s", ce)
            if ce.response["ResponseMetadata"]["HTTPStatusCode"] == 403:
                logger.error(
                    "Failed to collect inspector v2 findings for region=%s, "
                    "region might be disabled in the AWS console",
                    self.region,
                )
        finally:
            logger.debug("Checkpoint state time: %s", self._last_check_at)
            logger.info("Total findings discovered: %s", total_findings)
            self._save()

    def _save(self):
        self._state_store.update_state(
            self._state_key,
            {
                "last_check_at": math.trunc(self._last_check_at)
            },  # used math.trunc to truncate millisec value
        )

    def _load(self):
        state = self._state_store.get_state(self._state_key)
        if state:
            self._last_check_at = state["last_check_at"]


class AWSInspectorV2DataLoader:
    """Class for AWS inspector v2 data loader."""

    def __init__(self, config):
        self._config = config
        self._stopped = False
        self._lock = threading.Lock()
        self._cli, self._credentials = tacommon.get_service_client(
            self._config, tac.inspector_v2
        )

    def _do_indexing(self):
        if self._credentials.need_retire():
            self._cli, self._credentials = tacommon.get_service_client(
                self._config, tac.inspector_v2
            )
        account_id = self._credentials.account_id
        AWSInspectorV2FindingsDataLoader(self._config, self._cli, account_id).run()

    def __call__(self):
        if self._lock.locked():
            logger.info(
                "Last round of data collection for inspector v2 findings"
                "region=%s, datainput=%s is not done yet",
                self._config[tac.region],
                self._config[tac.datainput],
            )
            return

        logger.info(
            "Start collecting inspector v2 findings for region=%s, datainput=%s",
            self._config[tac.region],
            self._config[tac.datainput],
        )

        try:
            with self._lock:
                self._do_indexing()
        except Exception:  # pylint: disable=broad-except
            logger.error(
                "Failed to collect inspector v2 findings for region=%s, "
                "datainput=%s, error=%s",
                self._config[tac.region],
                self._config[tac.datainput],
                traceback.format_exc(),
            )

        logger.info(
            "End of collection for inspector v2 findings for region=%s, datainput=%s",
            self._config[tac.region],
            self._config[tac.datainput],
        )

    def get_interval(self):
        """Returns input polling interval."""
        return self._config[tac.polling_interval]

    def stop(self):
        """Stops the input."""
        self._stopped = True

    def stopped(self):
        """Returns if the input is stopped or not."""
        return self._stopped or self._config[tac.data_loader_mgr].stopped()

    def get_props(self):
        """Returns config."""
        return self._config
