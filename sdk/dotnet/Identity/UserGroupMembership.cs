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
    /// This resource provides the User Group Membership resource in Oracle Cloud Infrastructure Identity service.
    /// 
    /// Adds the specified user to the specified group and returns a `UserGroupMembership` object with its own OCID.
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
    ///         var testUserGroupMembership = new Oci.Identity.UserGroupMembership("testUserGroupMembership", new Oci.Identity.UserGroupMembershipArgs
    ///         {
    ///             GroupId = oci_identity_group.Test_group.Id,
    ///             UserId = oci_identity_user.Test_user.Id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// UserGroupMemberships can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:identity/userGroupMembership:UserGroupMembership test_user_group_membership "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:identity/userGroupMembership:UserGroupMembership")]
    public partial class UserGroupMembership : Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the tenancy containing the user, group, and membership object.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the group.
        /// </summary>
        [Output("groupId")]
        public Output<string> GroupId { get; private set; } = null!;

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Output("inactiveState")]
        public Output<string> InactiveState { get; private set; } = null!;

        /// <summary>
        /// The membership's current state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Date and time the membership was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Output("userId")]
        public Output<string> UserId { get; private set; } = null!;


        /// <summary>
        /// Create a UserGroupMembership resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public UserGroupMembership(string name, UserGroupMembershipArgs args, CustomResourceOptions? options = null)
            : base("oci:identity/userGroupMembership:UserGroupMembership", name, args ?? new UserGroupMembershipArgs(), MakeResourceOptions(options, ""))
        {
        }

        private UserGroupMembership(string name, Input<string> id, UserGroupMembershipState? state = null, CustomResourceOptions? options = null)
            : base("oci:identity/userGroupMembership:UserGroupMembership", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing UserGroupMembership resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static UserGroupMembership Get(string name, Input<string> id, UserGroupMembershipState? state = null, CustomResourceOptions? options = null)
        {
            return new UserGroupMembership(name, id, state, options);
        }
    }

    public sealed class UserGroupMembershipArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the tenancy containing the user, group, and membership object.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The OCID of the group.
        /// </summary>
        [Input("groupId", required: true)]
        public Input<string> GroupId { get; set; } = null!;

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Input("userId", required: true)]
        public Input<string> UserId { get; set; } = null!;

        public UserGroupMembershipArgs()
        {
        }
    }

    public sealed class UserGroupMembershipState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the tenancy containing the user, group, and membership object.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The OCID of the group.
        /// </summary>
        [Input("groupId")]
        public Input<string>? GroupId { get; set; }

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Input("inactiveState")]
        public Input<string>? InactiveState { get; set; }

        /// <summary>
        /// The membership's current state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Date and time the membership was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Input("userId")]
        public Input<string>? UserId { get; set; }

        public UserGroupMembershipState()
        {
        }
    }
}
