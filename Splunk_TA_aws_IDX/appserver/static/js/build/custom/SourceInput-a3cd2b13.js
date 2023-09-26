import{_ as s,a as e}from"./_rollupPluginBabelHelpers-deef47fd.js";import{o as c,p as o,i}from"./vendor-024cf9ec.js";var _=new(function(){function _(){e(this,_)}return s(_,[{key:"getMapData",value:function(){return[{service:"aws_billing",input:"billing"},{service:"aws_billing_cur",input:"billing"},{service:"aws_inspector",input:"inspector"},{service:"aws_inspector_v2",input:"inspector"},{service:"aws_kinesis",input:"vpc_flow_logs",format:"CloudWatchLogs",sourcetype:"aws:cloudwatchlogs:vpcflow"},{service:"aws_cloudwatch_logs",input:"vpc_flow_logs",sourcetype:"aws:cloudwatchlogs:vpcflow"},{service:"aws_s3",input:"aws_cloudtrail",sourcetype:"aws:cloudtrail"},{service:"aws_s3",input:"cloudfront_access_logs",sourcetype:"aws:cloudfront:accesslogs"},{service:"aws_s3",input:"elb_access_logs",sourcetype:"aws:elb:accesslogs"},{service:"aws_s3",input:"s3_access_logs",sourcetype:"aws:s3:accesslogs"},{service:"splunk_ta_aws_logs",input:"aws_cloudtrail",log_type:"cloudtrail"},{service:"splunk_ta_aws_logs",input:"cloudfront_access_logs",log_type:"cloudfront:accesslogs"},{service:"splunk_ta_aws_logs",input:"elb_access_logs",log_type:"elb:accesslogs"},{service:"splunk_ta_aws_logs",input:"s3_access_logs",log_type:"s3:accesslogs"},{service:"aws_sqs_based_s3",input:"aws_config",s3_file_decoder:"Config"},{service:"aws_sqs_based_s3",input:"aws_cloudtrail",s3_file_decoder:"CloudTrail"},{service:"aws_sqs_based_s3",input:"cloudfront_access_logs",s3_file_decoder:"CloudFrontAccessLogs"},{service:"aws_sqs_based_s3",input:"elb_access_logs",s3_file_decoder:"ELBAccessLogs"},{service:"aws_sqs_based_s3",input:"s3_access_logs",s3_file_decoder:"S3AccessLogs"},{service:"aws_sqs_based_s3",input:"vpc_flow_logs",s3_file_decoder:"VPCFlowLogs"},{service:"aws_sqs_based_s3",input:"delimited_files",s3_file_decoder:"DelimitedFilesDecoder"},{service:"aws_sqs_based_s3",input:"others",s3_file_decoder:"CustomLogs"},{service:"aws_sqs_based_s3",input:"aws_asl",s3_file_decoder:"AmazonSecurityLake",sourcetype:"aws:asl",sqs_sns_validation:!1}]}},{key:"getMockService",value:function(){return{billing:"Billing",vpc_flow_logs:"VPC Flow Logs",s3_access_logs:"S3 Access Logs",inspector:"Inspector",cloudfront_access_logs:"Cloudfront Access Logs",elb_access_logs:"ELB Access Logs",delimited_files:"Delimited Files",aws_asl:"Security Lake",others:"Custom Data Type"}}},{key:"detectSource",value:function(s,e){var _=l().filter((function(s){return s.service===e})),a=_.find((function(e){e=c(e,["service","input","sqs_sns_validation"]);var _=o(s,Object.keys(e));return i(e,_)}));return a&&"input"in a?a.input:e}}]),_}()),l=_.getMapData,a=_.getMockService,t=_.detectSource;export{l as a,t as d,a as g};
//# sourceMappingURL=SourceInput-a3cd2b13.js.map