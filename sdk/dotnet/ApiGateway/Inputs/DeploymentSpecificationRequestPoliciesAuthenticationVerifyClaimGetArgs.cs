// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesAuthenticationVerifyClaimGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Whether the claim is required to be present in the JWT or not. If set to "false", the claim values will be matched only if the claim is present in the JWT.
        /// </summary>
        [Input("isRequired")]
        public Input<bool>? IsRequired { get; set; }

        /// <summary>
        /// (Updatable) Name of the claim.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        [Input("values")]
        private InputList<string>? _values;

        /// <summary>
        /// (Updatable) A list of new values.  Each value can be a constant or may include one or more expressions enclosed within ${} delimiters.
        /// </summary>
        public InputList<string> Values
        {
            get => _values ?? (_values = new InputList<string>());
            set => _values = value;
        }

        public DeploymentSpecificationRequestPoliciesAuthenticationVerifyClaimGetArgs()
        {
        }
    }
}
