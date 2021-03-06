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
    public sealed class GetVmClusterNetworksVmClusterNetworkResult
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The list of DNS server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public readonly ImmutableArray<string> Dns;
        /// <summary>
        /// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string ExadataInfrastructureId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The list of NTP server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public readonly ImmutableArray<string> Ntps;
        /// <summary>
        /// The SCAN details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVmClusterNetworksVmClusterNetworkScanResult> Scans;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time when the VM cluster network was created.
        /// </summary>
        public readonly string TimeCreated;
        public readonly bool ValidateVmClusterNetwork;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated VM Cluster.
        /// </summary>
        public readonly string VmClusterId;
        /// <summary>
        /// Details of the client and backup networks.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVmClusterNetworksVmClusterNetworkVmNetworkResult> VmNetworks;

        [OutputConstructor]
        private GetVmClusterNetworksVmClusterNetworkResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableArray<string> dns,

            string exadataInfrastructureId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            ImmutableArray<string> ntps,

            ImmutableArray<Outputs.GetVmClusterNetworksVmClusterNetworkScanResult> scans,

            string state,

            string timeCreated,

            bool validateVmClusterNetwork,

            string vmClusterId,

            ImmutableArray<Outputs.GetVmClusterNetworksVmClusterNetworkVmNetworkResult> vmNetworks)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            Dns = dns;
            ExadataInfrastructureId = exadataInfrastructureId;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Ntps = ntps;
            Scans = scans;
            State = state;
            TimeCreated = timeCreated;
            ValidateVmClusterNetwork = validateVmClusterNetwork;
            VmClusterId = vmClusterId;
            VmNetworks = vmNetworks;
        }
    }
}
