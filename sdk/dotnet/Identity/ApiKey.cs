// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    /// <summary>
    /// This resource provides the Api Key resource in Oracle Cloud Infrastructure Identity service.
    /// 
    /// Uploads an API signing key for the specified user.
    /// 
    /// Every user has permission to use this operation to upload a key for *their own user ID*. An
    /// administrator in your organization does not need to write a policy to give users this ability.
    /// To compare, administrators who have permission to the tenancy can use this operation to upload a
    /// key for any user, including themselves.
    /// 
    /// **Important:** Even though you have permission to upload an API key, you might not yet
    /// have permission to do much else. If you try calling an operation unrelated to your own credential
    /// management (e.g., `ListUsers`, `LaunchInstance`) and receive an "unauthorized" error,
    /// check with an administrator to confirm which IAM Service group(s) you're in and what access
    /// you have. Also confirm you're working in the correct compartment.
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
    ///         var testApiKey = new Oci.Identity.ApiKey("testApiKey", new Oci.Identity.ApiKeyArgs
    ///         {
    ///             KeyValue = @var.Api_key_key_value,
    ///             UserId = oci_identity_user.Test_user.Id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// ApiKeys can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:identity/apiKey:ApiKey test_api_key "users/{userId}/apiKeys/{fingerprint}"
    /// ```
    /// </summary>
    [OciResourceType("oci:identity/apiKey:ApiKey")]
    public partial class ApiKey : Pulumi.CustomResource
    {
        /// <summary>
        /// The key's fingerprint (e.g., 12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef).
        /// </summary>
        [Output("fingerprint")]
        public Output<string> Fingerprint { get; private set; } = null!;

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Output("inactiveStatus")]
        public Output<string> InactiveStatus { get; private set; } = null!;

        /// <summary>
        /// The public key.  Must be an RSA key in PEM format.
        /// </summary>
        [Output("keyValue")]
        public Output<string> KeyValue { get; private set; } = null!;

        /// <summary>
        /// The API key's current state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Date and time the `ApiKey` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Output("userId")]
        public Output<string> UserId { get; private set; } = null!;


        /// <summary>
        /// Create a ApiKey resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ApiKey(string name, ApiKeyArgs args, CustomResourceOptions? options = null)
            : base("oci:identity/apiKey:ApiKey", name, args ?? new ApiKeyArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ApiKey(string name, Input<string> id, ApiKeyState? state = null, CustomResourceOptions? options = null)
            : base("oci:identity/apiKey:ApiKey", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ApiKey resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ApiKey Get(string name, Input<string> id, ApiKeyState? state = null, CustomResourceOptions? options = null)
        {
            return new ApiKey(name, id, state, options);
        }
    }

    public sealed class ApiKeyArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The public key.  Must be an RSA key in PEM format.
        /// </summary>
        [Input("keyValue", required: true)]
        public Input<string> KeyValue { get; set; } = null!;

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Input("userId", required: true)]
        public Input<string> UserId { get; set; } = null!;

        public ApiKeyArgs()
        {
        }
    }

    public sealed class ApiKeyState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The key's fingerprint (e.g., 12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef).
        /// </summary>
        [Input("fingerprint")]
        public Input<string>? Fingerprint { get; set; }

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Input("inactiveStatus")]
        public Input<string>? InactiveStatus { get; set; }

        /// <summary>
        /// The public key.  Must be an RSA key in PEM format.
        /// </summary>
        [Input("keyValue")]
        public Input<string>? KeyValue { get; set; }

        /// <summary>
        /// The API key's current state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Date and time the `ApiKey` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Input("userId")]
        public Input<string>? UserId { get; set; }

        public ApiKeyState()
        {
        }
    }
}
