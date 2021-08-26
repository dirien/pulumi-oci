// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersItemArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The original case-insensitive name of the header.  This name must be unique across transformation policies.
        /// </summary>
        [Input("from", required: true)]
        public Input<string> From { get; set; } = null!;

        /// <summary>
        /// (Updatable) The new name of the header.  This name must be unique across transformation policies.
        /// </summary>
        [Input("to", required: true)]
        public Input<string> To { get; set; } = null!;

        public DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersItemArgs()
        {
        }
    }
}
