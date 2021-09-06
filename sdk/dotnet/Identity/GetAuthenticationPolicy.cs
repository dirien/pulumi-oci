// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetAuthenticationPolicy
    {
        /// <summary>
        /// This data source provides details about a specific Authentication Policy resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Gets the authentication policy for the given tenancy. You must specify your tenant’s OCID as the value for
        /// the compartment ID (remember that the tenancy is simply the root compartment).
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
        ///         var testAuthenticationPolicy = Output.Create(Oci.Identity.GetAuthenticationPolicy.InvokeAsync(new Oci.Identity.GetAuthenticationPolicyArgs
        ///         {
        ///             CompartmentId = @var.Tenancy_ocid,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAuthenticationPolicyResult> InvokeAsync(GetAuthenticationPolicyArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAuthenticationPolicyResult>("oci:identity/getAuthenticationPolicy:getAuthenticationPolicy", args ?? new GetAuthenticationPolicyArgs(), options.WithVersion());
    }


    public sealed class GetAuthenticationPolicyArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        public GetAuthenticationPolicyArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAuthenticationPolicyResult
    {
        /// <summary>
        /// Compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string Id;
        /// <summary>
        /// Network policy, Consists of a list of Network Source ids.
        /// </summary>
        public readonly Outputs.GetAuthenticationPolicyNetworkPolicyResult NetworkPolicy;
        /// <summary>
        /// Password policy, currently set for the given compartment.
        /// </summary>
        public readonly Outputs.GetAuthenticationPolicyPasswordPolicyResult PasswordPolicy;

        [OutputConstructor]
        private GetAuthenticationPolicyResult(
            string compartmentId,

            string id,

            Outputs.GetAuthenticationPolicyNetworkPolicyResult networkPolicy,

            Outputs.GetAuthenticationPolicyPasswordPolicyResult passwordPolicy)
        {
            CompartmentId = compartmentId;
            Id = id;
            NetworkPolicy = networkPolicy;
            PasswordPolicy = passwordPolicy;
        }
    }
}
