// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class ApigatewayDeploymentSpecificationRouteResponsePoliciesHeaderTransformations
    {
        /// <summary>
        /// (Updatable) Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
        /// </summary>
        public readonly Outputs.ApigatewayDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeaders? FilterHeaders;
        /// <summary>
        /// (Updatable) Rename HTTP headers as they pass through the gateway.
        /// </summary>
        public readonly Outputs.ApigatewayDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeaders? RenameHeaders;
        /// <summary>
        /// (Updatable) Set HTTP headers as they pass through the gateway.
        /// </summary>
        public readonly Outputs.ApigatewayDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeaders? SetHeaders;

        [OutputConstructor]
        private ApigatewayDeploymentSpecificationRouteResponsePoliciesHeaderTransformations(
            Outputs.ApigatewayDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeaders? filterHeaders,

            Outputs.ApigatewayDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeaders? renameHeaders,

            Outputs.ApigatewayDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeaders? setHeaders)
        {
            FilterHeaders = filterHeaders;
            RenameHeaders = renameHeaders;
            SetHeaders = setHeaders;
        }
    }
}