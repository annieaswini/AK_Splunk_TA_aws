import{_ as e,a as i}from"./_rollupPluginBabelHelpers-deef47fd.js";var t=function(){function t(e,s,r,a,n){i(this,t),this.globalConfig=e,this.serviceName=s,this.el=r,this.row=a,this.field=n}return e(t,[{key:"render",value:function(e){var i="";if("aws_account"===this.serviceName||"aws_private_account"===this.serviceName)if("iam"===this.field)i=e.iam?"Yes":"No";else if("sts_private_endpoint_url"===this.field){i=e.sts_private_endpoint_url||"Not Provided"}return this.el.innerHTML=i,this}}]),t}();export{t as default};
//# sourceMappingURL=CustomAccountCell.js.map