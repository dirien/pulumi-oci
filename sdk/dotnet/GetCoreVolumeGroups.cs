// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetCoreVolumeGroups
    {
        /// <summary>
        /// This data source provides the list of Volume Groups in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the volume groups in the specified compartment and availability domain.
        /// For more information, see [Volume Groups](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/volumegroups.htm).
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
        ///         var testVolumeGroups = Output.Create(Oci.GetCoreVolumeGroups.InvokeAsync(new Oci.GetCoreVolumeGroupsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AvailabilityDomain = @var.Volume_group_availability_domain,
        ///             DisplayName = @var.Volume_group_display_name,
        ///             State = @var.Volume_group_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetCoreVolumeGroupsResult> InvokeAsync(GetCoreVolumeGroupsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCoreVolumeGroupsResult>("oci:index/getCoreVolumeGroups:GetCoreVolumeGroups", args ?? new GetCoreVolumeGroupsArgs(), options.WithVersion());
    }


    public sealed class GetCoreVolumeGroupsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetCoreVolumeGroupsFilterArgs>? _filters;
        public List<Inputs.GetCoreVolumeGroupsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetCoreVolumeGroupsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetCoreVolumeGroupsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetCoreVolumeGroupsResult
    {
        /// <summary>
        /// The availability domain of the volume group.
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The OCID of the compartment that contains the volume group.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name for the volume group. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetCoreVolumeGroupsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of a volume group.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of volume_groups.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCoreVolumeGroupsVolumeGroupResult> VolumeGroups;

        [OutputConstructor]
        private GetCoreVolumeGroupsResult(
            string? availabilityDomain,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetCoreVolumeGroupsFilterResult> filters,

            string id,

            string? state,

            ImmutableArray<Outputs.GetCoreVolumeGroupsVolumeGroupResult> volumeGroups)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
            VolumeGroups = volumeGroups;
        }
    }
}