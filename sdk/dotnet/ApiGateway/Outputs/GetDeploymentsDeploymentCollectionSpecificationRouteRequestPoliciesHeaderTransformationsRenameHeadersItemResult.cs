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
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemResult
    {
        /// <summary>
        /// The original case-insensitive name of the header.  This name must be unique across transformation policies.
        /// </summary>
        public readonly string From;
        /// <summary>
        /// The new name of the header.  This name must be unique across transformation policies.
        /// </summary>
        public readonly string To;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemResult(
            string from,

            string to)
        {
            From = from;
            To = to;
        }
    }
}
