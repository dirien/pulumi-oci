// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesAuthenticationGetArgs : Pulumi.ResourceArgs
    {
        [Input("audiences")]
        private InputList<string>? _audiences;

        /// <summary>
        /// (Updatable) The list of intended recipients for the token.
        /// </summary>
        public InputList<string> Audiences
        {
            get => _audiences ?? (_audiences = new InputList<string>());
            set => _audiences = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
        /// </summary>
        [Input("functionId")]
        public Input<string>? FunctionId { get; set; }

        /// <summary>
        /// (Updatable) Whether an unauthenticated user may access the API. Must be "true" to enable ANONYMOUS route authorization.
        /// </summary>
        [Input("isAnonymousAccessAllowed")]
        public Input<bool>? IsAnonymousAccessAllowed { get; set; }

        [Input("issuers")]
        private InputList<string>? _issuers;

        /// <summary>
        /// (Updatable) A list of parties that could have issued the token.
        /// </summary>
        public InputList<string> Issuers
        {
            get => _issuers ?? (_issuers = new InputList<string>());
            set => _issuers = value;
        }

        /// <summary>
        /// (Updatable) The maximum expected time difference between the system clocks of the token issuer and the API Gateway.
        /// </summary>
        [Input("maxClockSkewInSeconds")]
        public Input<double>? MaxClockSkewInSeconds { get; set; }

        /// <summary>
        /// (Updatable) A set of Public Keys that will be used to verify the JWT signature.
        /// </summary>
        [Input("publicKeys")]
        public Input<Inputs.DeploymentSpecificationRequestPoliciesAuthenticationPublicKeysGetArgs>? PublicKeys { get; set; }

        /// <summary>
        /// (Updatable) The authentication scheme that is to be used when authenticating the token. This must to be provided if "tokenHeader" is specified.
        /// </summary>
        [Input("tokenAuthScheme")]
        public Input<string>? TokenAuthScheme { get; set; }

        /// <summary>
        /// (Updatable) The name of the header containing the authentication token.
        /// </summary>
        [Input("tokenHeader")]
        public Input<string>? TokenHeader { get; set; }

        /// <summary>
        /// (Updatable) The name of the query parameter containing the authentication token.
        /// </summary>
        [Input("tokenQueryParam")]
        public Input<string>? TokenQueryParam { get; set; }

        /// <summary>
        /// (Updatable) Type of the Response Cache Store Policy.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        [Input("verifyClaims")]
        private InputList<Inputs.DeploymentSpecificationRequestPoliciesAuthenticationVerifyClaimGetArgs>? _verifyClaims;

        /// <summary>
        /// (Updatable) A list of claims which should be validated to consider the token valid.
        /// </summary>
        public InputList<Inputs.DeploymentSpecificationRequestPoliciesAuthenticationVerifyClaimGetArgs> VerifyClaims
        {
            get => _verifyClaims ?? (_verifyClaims = new InputList<Inputs.DeploymentSpecificationRequestPoliciesAuthenticationVerifyClaimGetArgs>());
            set => _verifyClaims = value;
        }

        public DeploymentSpecificationRequestPoliciesAuthenticationGetArgs()
        {
        }
    }
}
