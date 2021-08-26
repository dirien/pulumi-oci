// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsSetHeadersItemArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) If a header with the same name already exists in the request, OVERWRITE will overwrite the value, APPEND will append to the existing value, or SKIP will keep the existing value.
        /// </summary>
        [Input("ifExists")]
        public Input<string>? IfExists { get; set; }

        /// <summary>
        /// (Updatable) The case-insensitive name of the header.  This name must be unique across transformation policies.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        [Input("values", required: true)]
        private InputList<string>? _values;

        /// <summary>
        /// (Updatable) A list of new values.  Each value can be a constant or may include one or more expressions enclosed within ${} delimiters.
        /// </summary>
        public InputList<string> Values
        {
            get => _values ?? (_values = new InputList<string>());
            set => _values = value;
        }

        public DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsSetHeadersItemArgs()
        {
        }
    }
}
