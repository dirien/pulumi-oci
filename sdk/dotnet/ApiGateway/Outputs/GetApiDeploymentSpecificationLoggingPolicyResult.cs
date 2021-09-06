// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class GetApiDeploymentSpecificationLoggingPolicyResult
    {
        /// <summary>
        /// Configures the logging policies for the access logs of an API Deployment.
        /// </summary>
        public readonly Outputs.GetApiDeploymentSpecificationLoggingPolicyAccessLogResult AccessLog;
        /// <summary>
        /// Configures the logging policies for the execution logs of an API Deployment.
        /// </summary>
        public readonly Outputs.GetApiDeploymentSpecificationLoggingPolicyExecutionLogResult ExecutionLog;

        [OutputConstructor]
        private GetApiDeploymentSpecificationLoggingPolicyResult(
            Outputs.GetApiDeploymentSpecificationLoggingPolicyAccessLogResult accessLog,

            Outputs.GetApiDeploymentSpecificationLoggingPolicyExecutionLogResult executionLog)
        {
            AccessLog = accessLog;
            ExecutionLog = executionLog;
        }
    }
}
