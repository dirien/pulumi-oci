// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesRateLimitingGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The maximum number of requests per second to allow.
        /// </summary>
        [Input("rateInRequestsPerSecond", required: true)]
        public Input<int> RateInRequestsPerSecond { get; set; } = null!;

        /// <summary>
        /// (Updatable) The key used to group requests together.
        /// </summary>
        [Input("rateKey", required: true)]
        public Input<string> RateKey { get; set; } = null!;

        public DeploymentSpecificationRequestPoliciesRateLimitingGetArgs()
        {
        }
    }
}
