// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Outputs
{

    [OutputType]
    public sealed class KeyKeyShape
    {
        /// <summary>
        /// The algorithm used by a key's key versions to encrypt or decrypt.
        /// </summary>
        public readonly string Algorithm;
        /// <summary>
        /// Supported curve IDs for ECDSA keys.
        /// </summary>
        public readonly string? CurveId;
        /// <summary>
        /// The length of the key in bytes, expressed as an integer. Supported values include the following:
        /// * AES: 16, 24, or 32
        /// * RSA: 256, 384, or 512
        /// * ECDSA: 32, 48, or 66
        /// </summary>
        public readonly int Length;

        [OutputConstructor]
        private KeyKeyShape(
            string algorithm,

            string? curveId,

            int length)
        {
            Algorithm = algorithm;
            CurveId = curveId;
            Length = length;
        }
    }
}
