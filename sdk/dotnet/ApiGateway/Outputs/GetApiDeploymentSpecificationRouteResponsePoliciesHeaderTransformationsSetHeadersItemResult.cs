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
    public sealed class GetApiDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersItemResult
    {
        /// <summary>
        /// If a header with the same name already exists in the request, OVERWRITE will overwrite the value, APPEND will append to the existing value, or SKIP will keep the existing value.
        /// </summary>
        public readonly string IfExists;
        /// <summary>
        /// The case-insensitive name of the header.  This name must be unique across transformation policies.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// A list of new values.  Each value can be a constant or may include one or more expressions enclosed within ${} delimiters.
        /// </summary>
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private GetApiDeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersItemResult(
            string ifExists,

            string name,

            ImmutableArray<string> values)
        {
            IfExists = ifExists;
            Name = name;
            Values = values;
        }
    }
}
