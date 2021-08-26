// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetVirtualCircuits
    {
        /// <summary>
        /// This data source provides the list of Virtual Circuits in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the virtual circuits in the specified compartment.
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
        ///         var testVirtualCircuits = Output.Create(Oci.Core.GetVirtualCircuits.InvokeAsync(new Oci.Core.GetVirtualCircuitsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Virtual_circuit_display_name,
        ///             State = @var.Virtual_circuit_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVirtualCircuitsResult> InvokeAsync(GetVirtualCircuitsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVirtualCircuitsResult>("oci:core/getVirtualCircuits:getVirtualCircuits", args ?? new GetVirtualCircuitsArgs(), options.WithVersion());
    }


    public sealed class GetVirtualCircuitsArgs : Pulumi.InvokeArgs
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
        private List<Inputs.GetVirtualCircuitsFilterArgs>? _filters;
        public List<Inputs.GetVirtualCircuitsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVirtualCircuitsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetVirtualCircuitsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetVirtualCircuitsResult
    {
        /// <summary>
        /// The OCID of the compartment containing the virtual circuit.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetVirtualCircuitsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The virtual circuit's current state. For information about the different states, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of virtual_circuits.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualCircuitsVirtualCircuitResult> VirtualCircuits;

        [OutputConstructor]
        private GetVirtualCircuitsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetVirtualCircuitsFilterResult> filters,

            string id,

            string? state,

            ImmutableArray<Outputs.GetVirtualCircuitsVirtualCircuitResult> virtualCircuits)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
            VirtualCircuits = virtualCircuits;
        }
    }
}
