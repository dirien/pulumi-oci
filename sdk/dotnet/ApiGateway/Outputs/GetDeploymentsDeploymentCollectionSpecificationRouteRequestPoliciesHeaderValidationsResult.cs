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
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRouteRequestPoliciesHeaderValidationsResult
    {
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteRequestPoliciesHeaderValidationsHeaderResult> Headers;
        /// <summary>
        /// Validation behavior mode.
        /// </summary>
        public readonly string ValidationMode;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRouteRequestPoliciesHeaderValidationsResult(
            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteRequestPoliciesHeaderValidationsHeaderResult> headers,

            string validationMode)
        {
            Headers = headers;
            ValidationMode = validationMode;
        }
    }
}
