// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:database/autonomousDatabaseWallet:AutonomousDatabaseWallet")]
    public partial class AutonomousDatabaseWallet : Pulumi.CustomResource
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Output("autonomousDatabaseId")]
        public Output<string> AutonomousDatabaseId { get; private set; } = null!;

        [Output("base64EncodeContent")]
        public Output<bool?> Base64EncodeContent { get; private set; } = null!;

        /// <summary>
        /// content of the downloaded zipped wallet for the Autonomous Database. If `base64_encode_content` is set to `true`, then this content will be base64 encoded.
        /// </summary>
        [Output("content")]
        public Output<string> Content { get; private set; } = null!;

        /// <summary>
        /// The type of wallet to generate.
        /// </summary>
        [Output("generateType")]
        public Output<string?> GenerateType { get; private set; } = null!;

        /// <summary>
        /// The password to encrypt the keys inside the wallet. The password must be at least 8 characters long and must include at least 1 letter and either 1 numeric character or 1 special character.
        /// </summary>
        [Output("password")]
        public Output<string> Password { get; private set; } = null!;


        /// <summary>
        /// Create a AutonomousDatabaseWallet resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AutonomousDatabaseWallet(string name, AutonomousDatabaseWalletArgs args, CustomResourceOptions? options = null)
            : base("oci:database/autonomousDatabaseWallet:AutonomousDatabaseWallet", name, args ?? new AutonomousDatabaseWalletArgs(), MakeResourceOptions(options, ""))
        {
        }

        private AutonomousDatabaseWallet(string name, Input<string> id, AutonomousDatabaseWalletState? state = null, CustomResourceOptions? options = null)
            : base("oci:database/autonomousDatabaseWallet:AutonomousDatabaseWallet", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing AutonomousDatabaseWallet resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static AutonomousDatabaseWallet Get(string name, Input<string> id, AutonomousDatabaseWalletState? state = null, CustomResourceOptions? options = null)
        {
            return new AutonomousDatabaseWallet(name, id, state, options);
        }
    }

    public sealed class AutonomousDatabaseWalletArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId", required: true)]
        public Input<string> AutonomousDatabaseId { get; set; } = null!;

        [Input("base64EncodeContent")]
        public Input<bool>? Base64EncodeContent { get; set; }

        /// <summary>
        /// The type of wallet to generate.
        /// </summary>
        [Input("generateType")]
        public Input<string>? GenerateType { get; set; }

        /// <summary>
        /// The password to encrypt the keys inside the wallet. The password must be at least 8 characters long and must include at least 1 letter and either 1 numeric character or 1 special character.
        /// </summary>
        [Input("password", required: true)]
        public Input<string> Password { get; set; } = null!;

        public AutonomousDatabaseWalletArgs()
        {
        }
    }

    public sealed class AutonomousDatabaseWalletState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId")]
        public Input<string>? AutonomousDatabaseId { get; set; }

        [Input("base64EncodeContent")]
        public Input<bool>? Base64EncodeContent { get; set; }

        /// <summary>
        /// content of the downloaded zipped wallet for the Autonomous Database. If `base64_encode_content` is set to `true`, then this content will be base64 encoded.
        /// </summary>
        [Input("content")]
        public Input<string>? Content { get; set; }

        /// <summary>
        /// The type of wallet to generate.
        /// </summary>
        [Input("generateType")]
        public Input<string>? GenerateType { get; set; }

        /// <summary>
        /// The password to encrypt the keys inside the wallet. The password must be at least 8 characters long and must include at least 1 letter and either 1 numeric character or 1 special character.
        /// </summary>
        [Input("password")]
        public Input<string>? Password { get; set; }

        public AutonomousDatabaseWalletState()
        {
        }
    }
}
