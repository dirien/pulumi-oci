// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class ComputeCapacityReservationInstanceReservationConfig
    {
        /// <summary>
        /// (Updatable) The fault domain to use for instances created using this reservation configuration. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the capacity is available for an instance that does not specify a fault domain. To change the fault domain for a reservation, delete the reservation and create a new one in the preferred fault domain.
        /// </summary>
        public readonly string? FaultDomain;
        /// <summary>
        /// (Updatable) The shape requested when launching instances using reserved capacity. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance. You can list all available shapes by calling [ListComputeCapacityReservationInstanceShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/computeCapacityReservationInstanceShapes/ListComputeCapacityReservationInstanceShapes).
        /// </summary>
        public readonly string InstanceShape;
        /// <summary>
        /// (Updatable) The shape configuration requested when launching instances in a compute capacity reservation.
        /// </summary>
        public readonly Outputs.ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig? InstanceShapeConfig;
        /// <summary>
        /// (Updatable) The amount of capacity to reserve in this reservation configuration.
        /// </summary>
        public readonly string ReservedCount;
        /// <summary>
        /// The amount of capacity in use out of the total capacity reserved in this reservation configuration.
        /// </summary>
        public readonly string? UsedCount;

        [OutputConstructor]
        private ComputeCapacityReservationInstanceReservationConfig(
            string? faultDomain,

            string instanceShape,

            Outputs.ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig? instanceShapeConfig,

            string reservedCount,

            string? usedCount)
        {
            FaultDomain = faultDomain;
            InstanceShape = instanceShape;
            InstanceShapeConfig = instanceShapeConfig;
            ReservedCount = reservedCount;
            UsedCount = usedCount;
        }
    }
}
