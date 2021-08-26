// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetCrossConnectGroups
    {
        /// <summary>
        /// This data source provides the list of Cross Connect Groups in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the cross-connect groups in the specified compartment.
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
        ///         var testCrossConnectGroups = Output.Create(Oci.Core.GetCrossConnectGroups.InvokeAsync(new Oci.Core.GetCrossConnectGroupsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Cross_connect_group_display_name,
        ///             State = @var.Cross_connect_group_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetCrossConnectGroupsResult> InvokeAsync(GetCrossConnectGroupsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCrossConnectGroupsResult>("oci:core/getCrossConnectGroups:getCrossConnectGroups", args ?? new GetCrossConnectGroupsArgs(), options.WithVersion());
    }


    public sealed class GetCrossConnectGroupsArgs : Pulumi.InvokeArgs
    {
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
        private List<Inputs.GetCrossConnectGroupsFilterArgs>? _filters;
        public List<Inputs.GetCrossConnectGroupsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetCrossConnectGroupsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetCrossConnectGroupsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetCrossConnectGroupsResult
    {
        /// <summary>
        /// The OCID of the compartment containing the cross-connect group.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of cross_connect_groups.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCrossConnectGroupsCrossConnectGroupResult> CrossConnectGroups;
        /// <summary>
        /// The display name of a user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetCrossConnectGroupsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The cross-connect group's current state.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetCrossConnectGroupsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetCrossConnectGroupsCrossConnectGroupResult> crossConnectGroups,

            string? displayName,

            ImmutableArray<Outputs.GetCrossConnectGroupsFilterResult> filters,

            string id,

            string? state)
        {
            CompartmentId = compartmentId;
            CrossConnectGroups = crossConnectGroups;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
