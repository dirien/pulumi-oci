// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationLoggingPoliciesGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Configures the logging policies for the access logs of an API Deployment.
        /// </summary>
        [Input("accessLog")]
        public Input<Inputs.DeploymentSpecificationLoggingPoliciesAccessLogGetArgs>? AccessLog { get; set; }

        /// <summary>
        /// (Updatable) Configures the logging policies for the execution logs of an API Deployment.
        /// </summary>
        [Input("executionLog")]
        public Input<Inputs.DeploymentSpecificationLoggingPoliciesExecutionLogGetArgs>? ExecutionLog { get; set; }

        public DeploymentSpecificationLoggingPoliciesGetArgs()
        {
        }
    }
}
