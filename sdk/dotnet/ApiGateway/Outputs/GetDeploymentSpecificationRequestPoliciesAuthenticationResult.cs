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
    public sealed class GetDeploymentSpecificationRequestPoliciesAuthenticationResult
    {
        /// <summary>
        /// The list of intended recipients for the token.
        /// </summary>
        public readonly ImmutableArray<string> Audiences;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
        /// </summary>
        public readonly string FunctionId;
        /// <summary>
        /// Whether an unauthenticated user may access the API. Must be "true" to enable ANONYMOUS route authorization.
        /// </summary>
        public readonly bool IsAnonymousAccessAllowed;
        /// <summary>
        /// A list of parties that could have issued the token.
        /// </summary>
        public readonly ImmutableArray<string> Issuers;
        /// <summary>
        /// The maximum expected time difference between the system clocks of the token issuer and the API Gateway.
        /// </summary>
        public readonly double MaxClockSkewInSeconds;
        /// <summary>
        /// A set of Public Keys that will be used to verify the JWT signature.
        /// </summary>
        public readonly Outputs.GetDeploymentSpecificationRequestPoliciesAuthenticationPublicKeysResult PublicKeys;
        /// <summary>
        /// The authentication scheme that is to be used when authenticating the token. This must to be provided if "tokenHeader" is specified.
        /// </summary>
        public readonly string TokenAuthScheme;
        /// <summary>
        /// The name of the header containing the authentication token.
        /// </summary>
        public readonly string TokenHeader;
        /// <summary>
        /// The name of the query parameter containing the authentication token.
        /// </summary>
        public readonly string TokenQueryParam;
        /// <summary>
        /// Type of the Response Cache Store Policy.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// A list of claims which should be validated to consider the token valid.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRequestPoliciesAuthenticationVerifyClaimResult> VerifyClaims;

        [OutputConstructor]
        private GetDeploymentSpecificationRequestPoliciesAuthenticationResult(
            ImmutableArray<string> audiences,

            string functionId,

            bool isAnonymousAccessAllowed,

            ImmutableArray<string> issuers,

            double maxClockSkewInSeconds,

            Outputs.GetDeploymentSpecificationRequestPoliciesAuthenticationPublicKeysResult publicKeys,

            string tokenAuthScheme,

            string tokenHeader,

            string tokenQueryParam,

            string type,

            ImmutableArray<Outputs.GetDeploymentSpecificationRequestPoliciesAuthenticationVerifyClaimResult> verifyClaims)
        {
            Audiences = audiences;
            FunctionId = functionId;
            IsAnonymousAccessAllowed = isAnonymousAccessAllowed;
            Issuers = issuers;
            MaxClockSkewInSeconds = maxClockSkewInSeconds;
            PublicKeys = publicKeys;
            TokenAuthScheme = tokenAuthScheme;
            TokenHeader = tokenHeader;
            TokenQueryParam = tokenQueryParam;
            Type = type;
            VerifyClaims = verifyClaims;
        }
    }
}
