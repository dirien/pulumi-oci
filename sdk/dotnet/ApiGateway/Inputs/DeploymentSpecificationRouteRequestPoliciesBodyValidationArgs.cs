// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteRequestPoliciesBodyValidationArgs : Pulumi.ResourceArgs
    {
        [Input("contents")]
        private InputList<Inputs.DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs>? _contents;

        /// <summary>
        /// (Updatable) The content of the request body.
        /// </summary>
        public InputList<Inputs.DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs> Contents
        {
            get => _contents ?? (_contents = new InputList<Inputs.DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs>());
            set => _contents = value;
        }

        /// <summary>
        /// (Updatable) Determines if the parameter is required in the request.
        /// </summary>
        [Input("required")]
        public Input<bool>? Required { get; set; }

        /// <summary>
        /// (Updatable) Validation behavior mode.
        /// </summary>
        [Input("validationMode")]
        public Input<string>? ValidationMode { get; set; }

        public DeploymentSpecificationRouteRequestPoliciesBodyValidationArgs()
        {
        }
    }
}
