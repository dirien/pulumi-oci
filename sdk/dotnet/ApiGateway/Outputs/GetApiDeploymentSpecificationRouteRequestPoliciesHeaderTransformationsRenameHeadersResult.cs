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
    public sealed class GetApiDeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersResult
    {
        /// <summary>
        /// The list of headers.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemResult> Items;

        [OutputConstructor]
        private GetApiDeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersResult(ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemResult> items)
        {
            Items = items;
        }
    }
}
