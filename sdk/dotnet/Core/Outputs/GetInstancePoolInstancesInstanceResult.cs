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
    public sealed class GetInstancePoolInstancesInstanceResult
    {
        public readonly bool AutoTerminateInstanceOnDelete;
        /// <summary>
        /// The availability domain the instance is running in.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool DecrementSizeOnDelete;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The fault domain the instance is running in.
        /// </summary>
        public readonly string FaultDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
        /// </summary>
        public readonly string InstanceConfigurationId;
        public readonly string InstanceId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
        /// </summary>
        public readonly string InstancePoolId;
        /// <summary>
        /// The load balancer backends that are configured for the instance pool instance.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInstancePoolInstancesInstanceLoadBalancerBackendResult> LoadBalancerBackends;
        /// <summary>
        /// The region that contains the availability domain the instance is running in.
        /// </summary>
        public readonly string Region;
        /// <summary>
        /// The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetInstancePoolInstancesInstanceResult(
            bool autoTerminateInstanceOnDelete,

            string availabilityDomain,

            string compartmentId,

            bool decrementSizeOnDelete,

            string displayName,

            string faultDomain,

            string id,

            string instanceConfigurationId,

            string instanceId,

            string instancePoolId,

            ImmutableArray<Outputs.GetInstancePoolInstancesInstanceLoadBalancerBackendResult> loadBalancerBackends,

            string region,

            string shape,

            string state,

            string timeCreated)
        {
            AutoTerminateInstanceOnDelete = autoTerminateInstanceOnDelete;
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DecrementSizeOnDelete = decrementSizeOnDelete;
            DisplayName = displayName;
            FaultDomain = faultDomain;
            Id = id;
            InstanceConfigurationId = instanceConfigurationId;
            InstanceId = instanceId;
            InstancePoolId = instancePoolId;
            LoadBalancerBackends = loadBalancerBackends;
            Region = region;
            Shape = shape;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
