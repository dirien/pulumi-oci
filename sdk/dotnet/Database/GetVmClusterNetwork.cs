// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetVmClusterNetwork
    {
        /// <summary>
        /// This data source provides details about a specific Vm Cluster Network resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified VM cluster network. Applies to Exadata Cloud@Customer instances only.
        /// To get information about a cloud VM cluster in an Exadata Cloud Service instance, use the [GetCloudVmCluster ](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/GetCloudVmCluster) operation.
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
        ///         var testVmClusterNetwork = Output.Create(Oci.Database.GetVmClusterNetwork.InvokeAsync(new Oci.Database.GetVmClusterNetworkArgs
        ///         {
        ///             ExadataInfrastructureId = oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id,
        ///             VmClusterNetworkId = oci_database_vm_cluster_network.Test_vm_cluster_network.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVmClusterNetworkResult> InvokeAsync(GetVmClusterNetworkArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVmClusterNetworkResult>("oci:database/getVmClusterNetwork:getVmClusterNetwork", args ?? new GetVmClusterNetworkArgs(), options.WithVersion());
    }


    public sealed class GetVmClusterNetworkArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("exadataInfrastructureId", required: true)]
        public string ExadataInfrastructureId { get; set; } = null!;

        /// <summary>
        /// The VM cluster network [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("vmClusterNetworkId", required: true)]
        public string VmClusterNetworkId { get; set; } = null!;

        public GetVmClusterNetworkArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetVmClusterNetworkResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The user-friendly name for the VM cluster network. The name does not need to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The list of DNS server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public readonly ImmutableArray<string> Dns;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
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
        public readonly ImmutableArray<Outputs.GetVmClusterNetworkScanResult> Scans;
        /// <summary>
        /// The current state of the VM cluster network.
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
        public readonly string VmClusterNetworkId;
        /// <summary>
        /// Details of the client and backup networks.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVmClusterNetworkVmNetworkResult> VmNetworks;

        [OutputConstructor]
        private GetVmClusterNetworkResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableArray<string> dns,

            string exadataInfrastructureId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            ImmutableArray<string> ntps,

            ImmutableArray<Outputs.GetVmClusterNetworkScanResult> scans,

            string state,

            string timeCreated,

            bool validateVmClusterNetwork,

            string vmClusterId,

            string vmClusterNetworkId,

            ImmutableArray<Outputs.GetVmClusterNetworkVmNetworkResult> vmNetworks)
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
            VmClusterNetworkId = vmClusterNetworkId;
            VmNetworks = vmNetworks;
        }
    }
}
