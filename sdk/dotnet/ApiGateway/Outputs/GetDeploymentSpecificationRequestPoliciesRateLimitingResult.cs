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
    public sealed class GetDeploymentSpecificationRequestPoliciesRateLimitingResult
    {
        /// <summary>
        /// The maximum number of requests per second to allow.
        /// </summary>
        public readonly int RateInRequestsPerSecond;
        /// <summary>
        /// The key used to group requests together.
        /// </summary>
        public readonly string RateKey;

        [OutputConstructor]
        private GetDeploymentSpecificationRequestPoliciesRateLimitingResult(
            int rateInRequestsPerSecond,

            string rateKey)
        {
            RateInRequestsPerSecond = rateInRequestsPerSecond;
            RateKey = rateKey;
        }
    }
}
