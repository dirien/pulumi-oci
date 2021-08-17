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
    public sealed class ApigatewayDeploymentSpecificationRouteRequestPoliciesQueryParameterValidations
    {
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly ImmutableArray<Outputs.ApigatewayDeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameter> Parameters;
        /// <summary>
        /// (Updatable) Validation behavior mode.
        /// </summary>
        public readonly string? ValidationMode;

        [OutputConstructor]
        private ApigatewayDeploymentSpecificationRouteRequestPoliciesQueryParameterValidations(
            ImmutableArray<Outputs.ApigatewayDeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameter> parameters,

            string? validationMode)
        {
            Parameters = parameters;
            ValidationMode = validationMode;
        }
    }
}