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
    public sealed class GetDeploymentSpecificationRouteResponsePoliciesResult
    {
        /// <summary>
        /// A set of transformations to apply to HTTP headers that pass through the gateway.
        /// </summary>
        public readonly Outputs.GetDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsResult HeaderTransformations;
        /// <summary>
        /// Base policy for how a response from a backend is cached in the Response Cache.
        /// </summary>
        public readonly Outputs.GetDeploymentSpecificationRouteResponsePoliciesResponseCacheStoreResult ResponseCacheStore;

        [OutputConstructor]
        private GetDeploymentSpecificationRouteResponsePoliciesResult(
            Outputs.GetDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsResult headerTransformations,

            Outputs.GetDeploymentSpecificationRouteResponsePoliciesResponseCacheStoreResult responseCacheStore)
        {
            HeaderTransformations = headerTransformations;
            ResponseCacheStore = responseCacheStore;
        }
    }
}
