// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetComputeCapacityReservationInstances
    {
        /// <summary>
        /// This data source provides the list of Compute Capacity Reservation Instances in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the instances launched under a capacity reservation. You can filter results by specifying criteria.
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
        ///         var testComputeCapacityReservationInstances = Output.Create(Oci.Core.GetComputeCapacityReservationInstances.InvokeAsync(new Oci.Core.GetComputeCapacityReservationInstancesArgs
        ///         {
        ///             CapacityReservationId = oci_core_capacity_reservation.Test_capacity_reservation.Id,
        ///             AvailabilityDomain = @var.Compute_capacity_reservation_instance_availability_domain,
        ///             CompartmentId = @var.Compartment_id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetComputeCapacityReservationInstancesResult> InvokeAsync(GetComputeCapacityReservationInstancesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetComputeCapacityReservationInstancesResult>("oci:core/getComputeCapacityReservationInstances:getComputeCapacityReservationInstances", args ?? new GetComputeCapacityReservationInstancesArgs(), options.WithVersion());
    }


    public sealed class GetComputeCapacityReservationInstancesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The OCID of the compute capacity reservation.
        /// </summary>
        [Input("capacityReservationId", required: true)]
        public string CapacityReservationId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        [Input("filters")]
        private List<Inputs.GetComputeCapacityReservationInstancesFilterArgs>? _filters;
        public List<Inputs.GetComputeCapacityReservationInstancesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetComputeCapacityReservationInstancesFilterArgs>());
            set => _filters = value;
        }

        public GetComputeCapacityReservationInstancesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetComputeCapacityReservationInstancesResult
    {
        /// <summary>
        /// The availability domain the instance is running in.
        /// </summary>
        public readonly string? AvailabilityDomain;
        public readonly string CapacityReservationId;
        /// <summary>
        /// The list of capacity_reservation_instances.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetComputeCapacityReservationInstancesCapacityReservationInstanceResult> CapacityReservationInstances;
        /// <summary>
        /// The OCID of the compartment that contains the instance.
        /// </summary>
        public readonly string? CompartmentId;
        public readonly ImmutableArray<Outputs.GetComputeCapacityReservationInstancesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetComputeCapacityReservationInstancesResult(
            string? availabilityDomain,

            string capacityReservationId,

            ImmutableArray<Outputs.GetComputeCapacityReservationInstancesCapacityReservationInstanceResult> capacityReservationInstances,

            string? compartmentId,

            ImmutableArray<Outputs.GetComputeCapacityReservationInstancesFilterResult> filters,

            string id)
        {
            AvailabilityDomain = availabilityDomain;
            CapacityReservationId = capacityReservationId;
            CapacityReservationInstances = capacityReservationInstances;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
        }
    }
}
