// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetCloudExadataInfrastructuresCloudExadataInfrastructureResult
    {
        /// <summary>
        /// The name of the availability domain that the cloud Exadata infrastructure resource is located in.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The available storage can be allocated to the cloud Exadata infrastructure resource, in gigabytes (GB).
        /// </summary>
        public readonly int AvailableStorageSizeInGbs;
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The number of compute servers for the cloud Exadata infrastructure.
        /// </summary>
        public readonly int ComputeCount;
        /// <summary>
        /// The list of customer email addresses that receive information from Oracle about the specified Oracle Cloud Infrastructure Database service resource. Oracle uses these email addresses to send notifications about planned and unplanned software maintenance updates, information about system hardware, and other information needed by administrators. Up to 10 email addresses can be added to the customer contacts for a cloud Exadata infrastructure instance.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCloudExadataInfrastructuresCloudExadataInfrastructureCustomerContactResult> CustomerContacts;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
        /// </summary>
        public readonly string LastMaintenanceRunId;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        /// </summary>
        public readonly Outputs.GetCloudExadataInfrastructuresCloudExadataInfrastructureMaintenanceWindowResult MaintenanceWindow;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
        /// </summary>
        public readonly string NextMaintenanceRunId;
        /// <summary>
        /// The model name of the cloud Exadata infrastructure resource.
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The number of storage servers for the cloud Exadata infrastructure.
        /// </summary>
        public readonly int StorageCount;
        /// <summary>
        /// The date and time the cloud Exadata infrastructure resource was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The total storage allocated to the cloud Exadata infrastructure resource, in gigabytes (GB).
        /// </summary>
        public readonly int TotalStorageSizeInGbs;

        [OutputConstructor]
        private GetCloudExadataInfrastructuresCloudExadataInfrastructureResult(
            string availabilityDomain,

            int availableStorageSizeInGbs,

            string compartmentId,

            int computeCount,

            ImmutableArray<Outputs.GetCloudExadataInfrastructuresCloudExadataInfrastructureCustomerContactResult> customerContacts,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lastMaintenanceRunId,

            string lifecycleDetails,

            Outputs.GetCloudExadataInfrastructuresCloudExadataInfrastructureMaintenanceWindowResult maintenanceWindow,

            string nextMaintenanceRunId,

            string shape,

            string state,

            int storageCount,

            string timeCreated,

            int totalStorageSizeInGbs)
        {
            AvailabilityDomain = availabilityDomain;
            AvailableStorageSizeInGbs = availableStorageSizeInGbs;
            CompartmentId = compartmentId;
            ComputeCount = computeCount;
            CustomerContacts = customerContacts;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LastMaintenanceRunId = lastMaintenanceRunId;
            LifecycleDetails = lifecycleDetails;
            MaintenanceWindow = maintenanceWindow;
            NextMaintenanceRunId = nextMaintenanceRunId;
            Shape = shape;
            State = state;
            StorageCount = storageCount;
            TimeCreated = timeCreated;
            TotalStorageSizeInGbs = totalStorageSizeInGbs;
        }
    }
}
