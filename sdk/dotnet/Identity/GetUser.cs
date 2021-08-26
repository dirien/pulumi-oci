// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetUser
    {
        /// <summary>
        /// This data source provides details about a specific User resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Gets the specified user's information.
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
        ///         var testUser = Output.Create(Oci.Identity.GetUser.InvokeAsync(new Oci.Identity.GetUserArgs
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
        public static Task<GetUserResult> InvokeAsync(GetUserArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetUserResult>("oci:identity/getUser:getUser", args ?? new GetUserArgs(), options.WithVersion());
    }


    public sealed class GetUserArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Input("userId", required: true)]
        public string UserId { get; set; } = null!;

        public GetUserArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetUserResult
    {
        /// <summary>
        /// Properties indicating how the user is allowed to authenticate.
        /// </summary>
        public readonly Outputs.GetUserCapabilitiesResult Capabilities;
        /// <summary>
        /// The OCID of the tenancy containing the user.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The description you assign to the user. Does not have to be unique, and it's changeable.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The email address you assign to the user. The email address must be unique across all users in the tenancy.
        /// </summary>
        public readonly string Email;
        /// <summary>
        /// Whether the email address has been validated.
        /// </summary>
        public readonly bool EmailVerified;
        /// <summary>
        /// Identifier of the user in the identity provider
        /// </summary>
        public readonly string ExternalIdentifier;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the user.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the `IdentityProvider` this user belongs to.
        /// </summary>
        public readonly string IdentityProviderId;
        /// <summary>
        /// Returned only if the user's `lifecycleState` is INACTIVE. A 16-bit value showing the reason why the user is inactive:
        /// * bit 0: SUSPENDED (reserved for future use)
        /// * bit 1: DISABLED (reserved for future use)
        /// * bit 2: BLOCKED (the user has exceeded the maximum number of failed login attempts for the Console)
        /// </summary>
        public readonly string InactiveState;
        /// <summary>
        /// The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
        /// </summary>
        public readonly string LastSuccessfulLoginTime;
        /// <summary>
        /// The name you assign to the user during creation. This is the user's login for the Console. The name must be unique across all users in the tenancy and cannot be changed.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
        /// </summary>
        public readonly string PreviousSuccessfulLoginTime;
        /// <summary>
        /// The user's current state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Date and time the user was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        public readonly string UserId;

        [OutputConstructor]
        private GetUserResult(
            Outputs.GetUserCapabilitiesResult capabilities,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string email,

            bool emailVerified,

            string externalIdentifier,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string identityProviderId,

            string inactiveState,

            string lastSuccessfulLoginTime,

            string name,

            string previousSuccessfulLoginTime,

            string state,

            string timeCreated,

            string userId)
        {
            Capabilities = capabilities;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            Email = email;
            EmailVerified = emailVerified;
            ExternalIdentifier = externalIdentifier;
            FreeformTags = freeformTags;
            Id = id;
            IdentityProviderId = identityProviderId;
            InactiveState = inactiveState;
            LastSuccessfulLoginTime = lastSuccessfulLoginTime;
            Name = name;
            PreviousSuccessfulLoginTime = previousSuccessfulLoginTime;
            State = state;
            TimeCreated = timeCreated;
            UserId = userId;
        }
    }
}
