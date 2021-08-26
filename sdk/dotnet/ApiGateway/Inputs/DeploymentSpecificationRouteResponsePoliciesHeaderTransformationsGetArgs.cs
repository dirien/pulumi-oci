// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
        /// </summary>
        [Input("filterHeaders")]
        public Input<Inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeadersGetArgs>? FilterHeaders { get; set; }

        /// <summary>
        /// (Updatable) Rename HTTP headers as they pass through the gateway.
        /// </summary>
        [Input("renameHeaders")]
        public Input<Inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersGetArgs>? RenameHeaders { get; set; }

        /// <summary>
        /// (Updatable) Set HTTP headers as they pass through the gateway.
        /// </summary>
        [Input("setHeaders")]
        public Input<Inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersGetArgs>? SetHeaders { get; set; }

        public DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsGetArgs()
        {
        }
    }
}
