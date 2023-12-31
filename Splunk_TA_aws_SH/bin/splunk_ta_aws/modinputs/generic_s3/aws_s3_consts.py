#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
# pylint: disable=invalid-name
"""
Filer for AWS S3 constants.
"""
s3_log = "splunk_aws_generic_s3"
s3_log_ns = "splunk_ta_aws_s3"
server_host = "server_host"
version = "version"

ta_short_name = "aws_s3"
mod_name = "generic_aws_s3"
ta_name = "aws_s3"
myta_conf = "aws_s3"

start_time = "start_time"
host_name = "host_name"
bucket_name = "bucket_name"
bucket_region = "bucket_region"
key = "key"
key_object = "key_object"
default_host = "s3.amazonaws.com"
offset = "offset"
key_name = "key_name"
recursion_depth = "recursion_depth"
initial_scan_datetime = "initial_scan_datetime"
terminal_scan_datetime = "terminal_scan_datetime"
whitelist = "whitelist"
blacklist = "blacklist"
character_set = "character_set"
ct_blacklist = "ct_blacklist"
ct_excluded_events_index = "ct_excluded_events_index"
last_modified = "last_modified"
polling_interval = "polling_interval"
max_retries = "max_retries"
parse_csv_with_header = "parse_csv_with_header"
parse_csv_with_delimiter = "parse_csv_with_delimiter"

log_stanza = "aws_s3"
log_level = "level"

prefix = "prefix"


# CKPT
latest_last_modified = "latest_last_modified"
# the latest scanning S3 bucket start time
latest_scanned = "latest_scanned"
version = "version"
keys = "keys"
key_ckpt = "key_ckpt"
etag = "etag"
offset = "offset"
eof = "eof"
data_input = "data_input"
error_count = "error_count"
encoding = "encoding"
state = "state"
new = "new"
started = "started"
processing = "processing"
failed = "failed"
job_uid = "job_uid"
meta_fields = "__splunk_aws_s3_input_ckpt_meta_fields__"

# builtin sourcetypes
aws_cloudtrail = "aws:cloudtrail"
aws_elb_accesslogs = "aws:elb:accesslogs"
aws_s3_accesslogs = "aws:s3:accesslogs"
aws_cloudfront_accesslogs = "aws:cloudfront:accesslogs"
aws_s3 = "aws:s3"
