##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##
[logging]
log_level = DEBUG, INFO or ERROR

[global_settings]
use_hec = 0 or 1, use Http Event collector to inject data
hec_port = 8088, Http Event Collector port
use_kv_store = 0, Supported value for inspector v2 input is only 0
use_multiprocess = 0 or 1, use use_multiprocess to do data collection
