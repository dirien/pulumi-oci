// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class GetCertificatesCertificatePublicKeyInfoResult
    {
        /// <summary>
        /// The algorithm identifier and parameters for the public key.
        /// </summary>
        public readonly string Algorithm;
        /// <summary>
        /// The private key exponent.
        /// </summary>
        public readonly int Exponent;
        /// <summary>
        /// The number of bits in a key used by a cryptographic algorithm.
        /// </summary>
        public readonly int KeySize;

        [OutputConstructor]
        private GetCertificatesCertificatePublicKeyInfoResult(
            string algorithm,

            int exponent,

            int keySize)
        {
            Algorithm = algorithm;
            Exponent = exponent;
            KeySize = keySize;
        }
    }
}
