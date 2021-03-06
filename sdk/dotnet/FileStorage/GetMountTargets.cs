// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FileStorage
{
    public static class GetMountTargets
    {
        /// <summary>
        /// This data source provides the list of Mount Targets in Oracle Cloud Infrastructure File Storage service.
        /// 
        /// Lists the mount target resources in the specified compartment.
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
        ///         var testMountTargets = Output.Create(Oci.FileStorage.GetMountTargets.InvokeAsync(new Oci.FileStorage.GetMountTargetsArgs
        ///         {
        ///             AvailabilityDomain = @var.Mount_target_availability_domain,
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Mount_target_display_name,
        ///             ExportSetId = oci_file_storage_export_set.Test_export_set.Id,
        ///             Id = @var.Mount_target_id,
        ///             State = @var.Mount_target_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetMountTargetsResult> InvokeAsync(GetMountTargetsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetMountTargetsResult>("oci:filestorage/getMountTargets:getMountTargets", args ?? new GetMountTargetsArgs(), options.WithVersion());
    }


    public sealed class GetMountTargetsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public string AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export set.
        /// </summary>
        [Input("exportSetId")]
        public string? ExportSetId { get; set; }

        [Input("filters")]
        private List<Inputs.GetMountTargetsFilterArgs>? _filters;
        public List<Inputs.GetMountTargetsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetMountTargetsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// Filter results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetMountTargetsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetMountTargetsResult
    {
        /// <summary>
        /// The availability domain the mount target is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the mount target.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated export set. Controls what file systems will be exported through Network File System (NFS) protocol on this mount target.
        /// </summary>
        public readonly string? ExportSetId;
        public readonly ImmutableArray<Outputs.GetMountTargetsFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the mount target.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of mount_targets.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMountTargetsMountTargetResult> MountTargets;
        /// <summary>
        /// The current state of the mount target.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetMountTargetsResult(
            string availabilityDomain,

            string compartmentId,

            string? displayName,

            string? exportSetId,

            ImmutableArray<Outputs.GetMountTargetsFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetMountTargetsMountTargetResult> mountTargets,

            string? state)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            ExportSetId = exportSetId;
            Filters = filters;
            Id = id;
            MountTargets = mountTargets;
            State = state;
        }
    }
}
