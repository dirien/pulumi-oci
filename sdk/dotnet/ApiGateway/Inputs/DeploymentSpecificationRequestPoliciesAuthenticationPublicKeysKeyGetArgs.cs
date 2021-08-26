// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesAuthenticationPublicKeysKeyGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The algorithm intended for use with this key.
        /// </summary>
        [Input("alg")]
        public Input<string>? Alg { get; set; }

        /// <summary>
        /// (Updatable) The base64 url encoded exponent of the RSA public key represented by this key.
        /// </summary>
        [Input("e")]
        public Input<string>? E { get; set; }

        /// <summary>
        /// (Updatable) The format of the public key.
        /// </summary>
        [Input("format", required: true)]
        public Input<string> Format { get; set; } = null!;

        /// <summary>
        /// (Updatable) Name of the claim.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        [Input("keyOps")]
        private InputList<string>? _keyOps;

        /// <summary>
        /// (Updatable) The operations for which this key is to be used.
        /// </summary>
        public InputList<string> KeyOps
        {
            get => _keyOps ?? (_keyOps = new InputList<string>());
            set => _keyOps = value;
        }

        /// <summary>
        /// (Updatable) A unique key ID. This key will be used to verify the signature of a JWT with matching "kid".
        /// </summary>
        [Input("kid")]
        public Input<string>? Kid { get; set; }

        /// <summary>
        /// (Updatable) The key type.
        /// </summary>
        [Input("kty")]
        public Input<string>? Kty { get; set; }

        /// <summary>
        /// (Updatable) The base64 url encoded modulus of the RSA public key represented by this key.
        /// </summary>
        [Input("n")]
        public Input<string>? N { get; set; }

        /// <summary>
        /// (Updatable) The intended use of the public key.
        /// </summary>
        [Input("use")]
        public Input<string>? Use { get; set; }

        public DeploymentSpecificationRequestPoliciesAuthenticationPublicKeysKeyGetArgs()
        {
        }
    }
}
