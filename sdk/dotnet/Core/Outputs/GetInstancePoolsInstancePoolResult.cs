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
    public sealed class GetInstancePoolsInstancePoolResult
    {
        public readonly int ActualSize;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
        /// </summary>
        public readonly string InstanceConfigurationId;
        /// <summary>
        /// The load balancers attached to the instance pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInstancePoolsInstancePoolLoadBalancerResult> LoadBalancers;
        /// <summary>
        /// The placement configurations for the instance pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInstancePoolsInstancePoolPlacementConfigurationResult> PlacementConfigurations;
        /// <summary>
        /// The number of actual instances in the instance pool on the cloud. This attribute will be different when instance pool is used along with autoScaling Configuration.
        /// </summary>
        public readonly int Size;
        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the instance pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetInstancePoolsInstancePoolResult(
            int actualSize,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string instanceConfigurationId,

            ImmutableArray<Outputs.GetInstancePoolsInstancePoolLoadBalancerResult> loadBalancers,

            ImmutableArray<Outputs.GetInstancePoolsInstancePoolPlacementConfigurationResult> placementConfigurations,

            int size,

            string state,

            string timeCreated)
        {
            ActualSize = actualSize;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            InstanceConfigurationId = instanceConfigurationId;
            LoadBalancers = loadBalancers;
            PlacementConfigurations = placementConfigurations;
            Size = size;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
