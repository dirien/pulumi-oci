// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms
{
    public static class GetFleets
    {
        /// <summary>
        /// This data source provides the list of Fleets in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Returns a list of all the Fleets contained by a compartment.
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
        ///         var testFleets = Output.Create(Oci.Jms.GetFleets.InvokeAsync(new Oci.Jms.GetFleetsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Fleet_display_name,
        ///             Id = @var.Fleet_id,
        ///             State = @var.Fleet_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetFleetsResult> InvokeAsync(GetFleetsArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetFleetsResult>("oci:jms/getFleets:getFleets", args ?? new GetFleetsArgs(), options.WithVersion());
    }


    public sealed class GetFleetsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// The display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetFleetsFilterArgs>? _filters;
        public List<Inputs.GetFleetsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetFleetsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The ID of the Fleet.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// The state of the lifecycle.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetFleetsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetFleetsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of the Fleet.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The name of the Fleet.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetFleetsFilterResult> Filters;
        /// <summary>
        /// The list of fleet_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetsFleetCollectionResult> FleetCollections;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The lifecycle state of the Fleet.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetFleetsResult(
            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetFleetsFilterResult> filters,

            ImmutableArray<Outputs.GetFleetsFleetCollectionResult> fleetCollections,

            string? id,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            FleetCollections = fleetCollections;
            Id = id;
            State = state;
        }
    }
}
