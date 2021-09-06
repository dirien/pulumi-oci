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
    public sealed class GetDeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderResult
    {
        /// <summary>
        /// The case-insensitive name of the header.  This name must be unique across transformation policies.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Determines if the parameter is required in the request.
        /// </summary>
        public readonly bool Required;

        [OutputConstructor]
        private GetDeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderResult(
            string name,

            bool required)
        {
            Name = name;
            Required = required;
        }
    }
}
