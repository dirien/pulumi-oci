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
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRequestPoliciesAuthenticationVerifyClaimResult
    {
        /// <summary>
        /// Whether the claim is required to be present in the JWT or not. If set to "false", the claim values will be matched only if the claim is present in the JWT.
        /// </summary>
        public readonly bool IsRequired;
        /// <summary>
        /// Name of the claim.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// A list of new values.  Each value can be a constant or may include one or more expressions enclosed within ${} delimiters.
        /// </summary>
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRequestPoliciesAuthenticationVerifyClaimResult(
            bool isRequired,

            string key,

            ImmutableArray<string> values)
        {
            IsRequired = isRequired;
            Key = key;
            Values = values;
        }
    }
}
