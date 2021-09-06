// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    /// <summary>
    /// This resource provides the Volume Backup Policy Assignment resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// Assigns a volume backup policy to the specified volume. Note that a given volume can
    /// only have one backup policy assigned to it. If this operation is used for a volume that already
    /// has a different backup policy assigned, the prior backup policy will be silently unassigned.
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
    ///         var testVolumeBackupPolicyAssignment = new Oci.Core.VolumeBackupPolicyAssignment("testVolumeBackupPolicyAssignment", new Oci.Core.VolumeBackupPolicyAssignmentArgs
    ///         {
    ///             AssetId = oci_core_volume.Test_volume.Id,
    ///             PolicyId = oci_core_volume_backup_policy.Test_volume_backup_policy.Id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// VolumeBackupPolicyAssignments can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment test_volume_backup_policy_assignment "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment")]
    public partial class VolumeBackupPolicyAssignment : Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the volume to assign the policy to.
        /// </summary>
        [Output("assetId")]
        public Output<string> AssetId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the volume backup policy to assign to the volume.
        /// </summary>
        [Output("policyId")]
        public Output<string> PolicyId { get; private set; } = null!;

        /// <summary>
        /// The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;


        /// <summary>
        /// Create a VolumeBackupPolicyAssignment resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public VolumeBackupPolicyAssignment(string name, VolumeBackupPolicyAssignmentArgs args, CustomResourceOptions? options = null)
            : base("oci:core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment", name, args ?? new VolumeBackupPolicyAssignmentArgs(), MakeResourceOptions(options, ""))
        {
        }

        private VolumeBackupPolicyAssignment(string name, Input<string> id, VolumeBackupPolicyAssignmentState? state = null, CustomResourceOptions? options = null)
            : base("oci:core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing VolumeBackupPolicyAssignment resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static VolumeBackupPolicyAssignment Get(string name, Input<string> id, VolumeBackupPolicyAssignmentState? state = null, CustomResourceOptions? options = null)
        {
            return new VolumeBackupPolicyAssignment(name, id, state, options);
        }
    }

    public sealed class VolumeBackupPolicyAssignmentArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the volume to assign the policy to.
        /// </summary>
        [Input("assetId", required: true)]
        public Input<string> AssetId { get; set; } = null!;

        /// <summary>
        /// The OCID of the volume backup policy to assign to the volume.
        /// </summary>
        [Input("policyId", required: true)]
        public Input<string> PolicyId { get; set; } = null!;

        public VolumeBackupPolicyAssignmentArgs()
        {
        }
    }

    public sealed class VolumeBackupPolicyAssignmentState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the volume to assign the policy to.
        /// </summary>
        [Input("assetId")]
        public Input<string>? AssetId { get; set; }

        /// <summary>
        /// The OCID of the volume backup policy to assign to the volume.
        /// </summary>
        [Input("policyId")]
        public Input<string>? PolicyId { get; set; }

        /// <summary>
        /// The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        public VolumeBackupPolicyAssignmentState()
        {
        }
    }
}
