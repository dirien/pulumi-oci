// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms
{
    /// <summary>
    /// This resource provides the Sign resource in Oracle Cloud Infrastructure Kms service.
    /// 
    /// Creates a digital signature for a message or message digest by using the private key of a public-private key pair,
    /// also known as an asymmetric key. To verify the generated signature, you can use the [Verify](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/VerifiedData/Verify)
    /// operation. Or, if you want to validate the signature outside of the service, you can do so by using the public key of the same asymmetric key.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testSign = new Oci.Kms.Sign("testSign", new Oci.Kms.SignArgs
    ///         {
    ///             CryptoEndpoint = @var.Sign_message_crypto_endpoint,
    ///             KeyId = oci_kms_key.Test_key.Id,
    ///             Message = @var.Sign_message,
    ///             SigningAlgorithm = @var.Sign_signing_algorithm,
    ///             KeyVersionId = oci_kms_key_version.Test_key_version.Id,
    ///             MessageType = @var.Sign_message_type,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Sign can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:kms/sign:Sign test_sign "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:kms/sign:Sign")]
    public partial class Sign : Pulumi.CustomResource
    {
        /// <summary>
        /// The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,', 'GenerateDataEncryptionKey', 'Sign' and 'Verify' operations. see Vault Crypto endpoint.
        /// </summary>
        [Output("cryptoEndpoint")]
        public Output<string> CryptoEndpoint { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key used to sign the message.
        /// </summary>
        [Output("keyId")]
        public Output<string> KeyId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key version used to sign the message.
        /// </summary>
        [Output("keyVersionId")]
        public Output<string> KeyVersionId { get; private set; } = null!;

        /// <summary>
        /// The base64-encoded binary data object denoting the message or message digest to sign. You can have a message up to 4096 bytes in size. To sign a larger message, provide the message digest.
        /// </summary>
        [Output("message")]
        public Output<string> Message { get; private set; } = null!;

        /// <summary>
        /// Denotes whether the value of the message parameter is a raw message or a message digest.  The default value, `RAW`, indicates a message. To indicate a message digest, use `DIGEST`.
        /// </summary>
        [Output("messageType")]
        public Output<string> MessageType { get; private set; } = null!;

        /// <summary>
        /// The base64-encoded binary data object denoting the cryptographic signature generated for the message or message digest.
        /// </summary>
        [Output("signature")]
        public Output<string> Signature { get; private set; } = null!;

        /// <summary>
        /// The algorithm to use to sign the message or message digest. For RSA keys, supported signature schemes include PKCS #1 and RSASSA-PSS, along with  different hashing algorithms.  For ECDSA keys, ECDSA is the supported signature scheme with different hashing algorithms. When you pass a message digest for signing, ensure that you specify the same hashing algorithm  as used when creating the message digest.
        /// </summary>
        [Output("signingAlgorithm")]
        public Output<string> SigningAlgorithm { get; private set; } = null!;


        /// <summary>
        /// Create a Sign resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Sign(string name, SignArgs args, CustomResourceOptions? options = null)
            : base("oci:kms/sign:Sign", name, args ?? new SignArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Sign(string name, Input<string> id, SignState? state = null, CustomResourceOptions? options = null)
            : base("oci:kms/sign:Sign", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing Sign resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Sign Get(string name, Input<string> id, SignState? state = null, CustomResourceOptions? options = null)
        {
            return new Sign(name, id, state, options);
        }
    }

    public sealed class SignArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,', 'GenerateDataEncryptionKey', 'Sign' and 'Verify' operations. see Vault Crypto endpoint.
        /// </summary>
        [Input("cryptoEndpoint", required: true)]
        public Input<string> CryptoEndpoint { get; set; } = null!;

        /// <summary>
        /// The OCID of the key used to sign the message.
        /// </summary>
        [Input("keyId", required: true)]
        public Input<string> KeyId { get; set; } = null!;

        /// <summary>
        /// The OCID of the key version used to sign the message.
        /// </summary>
        [Input("keyVersionId")]
        public Input<string>? KeyVersionId { get; set; }

        /// <summary>
        /// The base64-encoded binary data object denoting the message or message digest to sign. You can have a message up to 4096 bytes in size. To sign a larger message, provide the message digest.
        /// </summary>
        [Input("message", required: true)]
        public Input<string> Message { get; set; } = null!;

        /// <summary>
        /// Denotes whether the value of the message parameter is a raw message or a message digest.  The default value, `RAW`, indicates a message. To indicate a message digest, use `DIGEST`.
        /// </summary>
        [Input("messageType")]
        public Input<string>? MessageType { get; set; }

        /// <summary>
        /// The algorithm to use to sign the message or message digest. For RSA keys, supported signature schemes include PKCS #1 and RSASSA-PSS, along with  different hashing algorithms.  For ECDSA keys, ECDSA is the supported signature scheme with different hashing algorithms. When you pass a message digest for signing, ensure that you specify the same hashing algorithm  as used when creating the message digest.
        /// </summary>
        [Input("signingAlgorithm", required: true)]
        public Input<string> SigningAlgorithm { get; set; } = null!;

        public SignArgs()
        {
        }
    }

    public sealed class SignState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,', 'GenerateDataEncryptionKey', 'Sign' and 'Verify' operations. see Vault Crypto endpoint.
        /// </summary>
        [Input("cryptoEndpoint")]
        public Input<string>? CryptoEndpoint { get; set; }

        /// <summary>
        /// The OCID of the key used to sign the message.
        /// </summary>
        [Input("keyId")]
        public Input<string>? KeyId { get; set; }

        /// <summary>
        /// The OCID of the key version used to sign the message.
        /// </summary>
        [Input("keyVersionId")]
        public Input<string>? KeyVersionId { get; set; }

        /// <summary>
        /// The base64-encoded binary data object denoting the message or message digest to sign. You can have a message up to 4096 bytes in size. To sign a larger message, provide the message digest.
        /// </summary>
        [Input("message")]
        public Input<string>? Message { get; set; }

        /// <summary>
        /// Denotes whether the value of the message parameter is a raw message or a message digest.  The default value, `RAW`, indicates a message. To indicate a message digest, use `DIGEST`.
        /// </summary>
        [Input("messageType")]
        public Input<string>? MessageType { get; set; }

        /// <summary>
        /// The base64-encoded binary data object denoting the cryptographic signature generated for the message or message digest.
        /// </summary>
        [Input("signature")]
        public Input<string>? Signature { get; set; }

        /// <summary>
        /// The algorithm to use to sign the message or message digest. For RSA keys, supported signature schemes include PKCS #1 and RSASSA-PSS, along with  different hashing algorithms.  For ECDSA keys, ECDSA is the supported signature scheme with different hashing algorithms. When you pass a message digest for signing, ensure that you specify the same hashing algorithm  as used when creating the message digest.
        /// </summary>
        [Input("signingAlgorithm")]
        public Input<string>? SigningAlgorithm { get; set; }

        public SignState()
        {
        }
    }
}