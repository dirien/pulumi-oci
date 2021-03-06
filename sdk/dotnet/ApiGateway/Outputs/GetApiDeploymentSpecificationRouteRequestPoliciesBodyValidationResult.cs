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
    public sealed class GetApiDeploymentSpecificationRouteRequestPoliciesBodyValidationResult
    {
        /// <summary>
        /// The content of the request body.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteRequestPoliciesBodyValidationContentResult> Contents;
        /// <summary>
        /// Determines if the parameter is required in the request.
        /// </summary>
        public readonly bool Required;
        /// <summary>
        /// Validation behavior mode.
        /// </summary>
        public readonly string ValidationMode;

        [OutputConstructor]
        private GetApiDeploymentSpecificationRouteRequestPoliciesBodyValidationResult(
            ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteRequestPoliciesBodyValidationContentResult> contents,

            bool required,

            string validationMode)
        {
            Contents = contents;
            Required = required;
            ValidationMode = validationMode;
        }
    }
}
