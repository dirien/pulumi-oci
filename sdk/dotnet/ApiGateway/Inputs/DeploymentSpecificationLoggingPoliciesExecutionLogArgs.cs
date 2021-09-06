// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationLoggingPoliciesExecutionLogArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Whether this policy is currently enabled.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// (Updatable) Specifies the log level used to control logging output of execution logs. Enabling logging at a given level also enables logging at all higher levels.
        /// </summary>
        [Input("logLevel")]
        public Input<string>? LogLevel { get; set; }

        public DeploymentSpecificationLoggingPoliciesExecutionLogArgs()
        {
        }
    }
}
