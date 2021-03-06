// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetVlans
    {
        /// <summary>
        /// This data source provides the list of Vlans in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the VLANs in the specified VCN and the specified compartment.
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
        ///         var testVlans = Output.Create(Oci.Core.GetVlans.InvokeAsync(new Oci.Core.GetVlansArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Vlan_display_name,
        ///             State = @var.Vlan_state,
        ///             VcnId = oci_core_vcn.Test_vcn.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVlansResult> InvokeAsync(GetVlansArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVlansResult>("oci:core/getVlans:getVlans", args ?? new GetVlansArgs(), options.WithVersion());
    }


    public sealed class GetVlansArgs : Pulumi.InvokeArgs
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
        private List<Inputs.GetVlansFilterArgs>? _filters;
        public List<Inputs.GetVlansFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVlansFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        /// </summary>
        [Input("vcnId")]
        public string? VcnId { get; set; }

        public GetVlansArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetVlansResult
    {
        /// <summary>
        /// The OCID of the compartment containing the VLAN.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetVlansFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The VLAN's current state.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The OCID of the VCN the VLAN is in.
        /// </summary>
        public readonly string? VcnId;
        /// <summary>
        /// The list of vlans.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVlansVlanResult> Vlans;

        [OutputConstructor]
        private GetVlansResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetVlansFilterResult> filters,

            string id,

            string? state,

            string? vcnId,

            ImmutableArray<Outputs.GetVlansVlanResult> vlans)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
            VcnId = vcnId;
            Vlans = vlans;
        }
    }
}
