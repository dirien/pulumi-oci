// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetApiKeys
    {
        /// <summary>
        /// This data source provides the list of Api Keys in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Lists the API signing keys for the specified user. A user can have a maximum of three keys.
        /// 
        /// Every user has permission to use this API call for *their own user ID*.  An administrator in your
        /// organization does not need to write a policy to give users this ability.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testApiKeys = Output.Create(Oci.Identity.GetApiKeys.InvokeAsync(new Oci.Identity.GetApiKeysArgs
        ///         {
        ///             UserId = oci_identity_user.Test_user.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetApiKeysResult> InvokeAsync(GetApiKeysArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetApiKeysResult>("oci:identity/getApiKeys:getApiKeys", args ?? new GetApiKeysArgs(), options.WithVersion());
    }


    public sealed class GetApiKeysArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetApiKeysFilterArgs>? _filters;
        public List<Inputs.GetApiKeysFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetApiKeysFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Input("userId", required: true)]
        public string UserId { get; set; } = null!;

        public GetApiKeysArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetApiKeysResult
    {
        /// <summary>
        /// The list of api_keys.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiKeysApiKeyResult> ApiKeys;
        public readonly ImmutableArray<Outputs.GetApiKeysFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the user the key belongs to.
        /// </summary>
        public readonly string UserId;

        [OutputConstructor]
        private GetApiKeysResult(
            ImmutableArray<Outputs.GetApiKeysApiKeyResult> apiKeys,

            ImmutableArray<Outputs.GetApiKeysFilterResult> filters,

            string id,

            string userId)
        {
            ApiKeys = apiKeys;
            Filters = filters;
            Id = id;
            UserId = userId;
        }
    }
}
