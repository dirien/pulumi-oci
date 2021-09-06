// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersArgs : Pulumi.ResourceArgs
    {
        [Input("items", required: true)]
        private InputList<Inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersItemArgs>? _items;

        /// <summary>
        /// (Updatable) The list of headers.
        /// </summary>
        public InputList<Inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersItemArgs>());
            set => _items = value;
        }

        public DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersArgs()
        {
        }
    }
}
