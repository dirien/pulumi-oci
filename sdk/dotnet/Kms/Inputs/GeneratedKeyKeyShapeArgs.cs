// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Inputs
{

    public sealed class GeneratedKeyKeyShapeArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The algorithm used by a key's key versions to encrypt or decrypt.
        /// </summary>
        [Input("algorithm", required: true)]
        public Input<string> Algorithm { get; set; } = null!;

        /// <summary>
        /// Supported curve IDs for ECDSA keys.
        /// </summary>
        [Input("curveId")]
        public Input<string>? CurveId { get; set; }

        /// <summary>
        /// The length of the key in bytes, expressed as an integer. Supported values include the following:
        /// * AES: 16, 24, or 32
        /// * RSA: 256, 384, or 512
        /// * ECDSA: 32, 48, or 66
        /// </summary>
        [Input("length", required: true)]
        public Input<int> Length { get; set; } = null!;

        public GeneratedKeyKeyShapeArgs()
        {
        }
    }
}
