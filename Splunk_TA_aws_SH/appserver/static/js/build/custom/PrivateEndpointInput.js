import{_ as e,a as t,i,h as n}from"./_rollupPluginBabelHelpers-deef47fd.js";import{$ as s,t as a}from"./vendor-024cf9ec.js";var l='\x3c!--htmlhint spec-char-escape:false --\x3e\n<!DOCTYPE html>\n\x3c!--\n-- SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>\n-- SPDX-License-Identifier: LicenseRef-Splunk-8-2021\n--\n--\x3e\n\n<div style="display: flex;height: 32px;">\n    <input id="private-endpoint-checkbox" type="checkbox" name="private_endpoint_enabled" <%- checked %>/>\n    <div data-test="help" id="help-text-private-ednpoint-checkbox" class="private-endpoint-help-text">\n        If enabled, User provided private endpoints will be used while making API calls to AWS services.\n    </div>\n</div>\n',c={aws_private_account:["sts"],aws_sqs_based_s3:["sqs","s3","sts"],aws_cloudtrail:["sqs","s3","sts"],aws_cloudwatch_logs:["logs","sts"],aws_kinesis:["kinesis","sts"],aws_cloudwatch:["sts","monitoring","elb","ec2","autoscaling","lambda","s3"]},r=function(){function r(e,i,n,s,a){t(this,r),this.globalConfig=e,this.el=i,this.data=n,this.util=a,this.setValue=s,this.endpoint_inputs=c[this.data.serviceName]||["s3","sts"]}return e(r,[{key:"render",value:function(){var e=this;return this.el.innerHTML=this._RenderTemplate(),s("input#private-endpoint-checkbox").on("change",(function(){return e._onCheckBoxChange()})),this}},{key:"_RenderTemplate",value:function(){if(parseInt(this.data.value)){var e,t=i(this.endpoint_inputs);try{for(t.s();!(e=t.n()).done;){var n=e.value;this._setVisibility(n,!0)}}catch(e){t.e(e)}finally{t.f()}return a(l)({checked:"checked"})}return a(l)({checked:""})}},{key:"_onCheckBoxChange",value:function(){var e=s("input#private-endpoint-checkbox").is(":checked"),t=e?1:0;this.setValue(t);var n,a=i(this.endpoint_inputs);try{for(a.s();!(n=a.n()).done;){var l=n.value;this._setVisibility(l,e)}}catch(e){a.e(e)}finally{a.f()}}},{key:"_setVisibility",value:function(e,t){var i="".concat(e,"_private_endpoint_url");this.util.setState((function(e){var s=n({},e.data);return s[i].display=t,{data:s}}))}}]),r}();export{r as default};
//# sourceMappingURL=PrivateEndpointInput.js.map
