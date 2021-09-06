// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate
{
    public static class GetDeployment
    {
        /// <summary>
        /// This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Retrieves a deployment.
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
        ///         var testDeployment = Output.Create(Oci.GoldenGate.GetDeployment.InvokeAsync(new Oci.GoldenGate.GetDeploymentArgs
        ///         {
        ///             DeploymentId = oci_golden_gate_deployment.Test_deployment.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDeploymentResult> InvokeAsync(GetDeploymentArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDeploymentResult>("oci:goldengate/getDeployment:getDeployment", args ?? new GetDeploymentArgs(), options.WithVersion());
    }


    public sealed class GetDeploymentArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// A unique Deployment identifier.
        /// </summary>
        [Input("deploymentId", required: true)]
        public string DeploymentId { get; set; } = null!;

        public GetDeploymentArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDeploymentResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The Minimum number of OCPUs to be made available for this Deployment.
        /// </summary>
        public readonly int CpuCoreCount;
        /// <summary>
        /// Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
        /// </summary>
        public readonly string DeploymentBackupId;
        public readonly string DeploymentId;
        /// <summary>
        /// The deployment type.
        /// </summary>
        public readonly string DeploymentType;
        /// <summary>
        /// The URL of a resource.
        /// </summary>
        public readonly string DeploymentUrl;
        /// <summary>
        /// Metadata about this specific object.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// An object's Display Name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A three-label Fully Qualified Domain Name (FQDN) for a resource.
        /// </summary>
        public readonly string Fqdn;
        /// <summary>
        /// A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates if auto scaling is enabled for the Deployment's CPU core count.
        /// </summary>
        public readonly bool IsAutoScalingEnabled;
        /// <summary>
        /// True if all of the aggregate resources are working correctly.
        /// </summary>
        public readonly bool IsHealthy;
        /// <summary>
        /// Indicates if the resource is the the latest available version.
        /// </summary>
        public readonly bool IsLatestVersion;
        /// <summary>
        /// True if this object is publicly available.
        /// </summary>
        public readonly bool IsPublic;
        /// <summary>
        /// The Oracle license model that applies to a Deployment.
        /// </summary>
        public readonly string LicenseModel;
        /// <summary>
        /// Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// An array of [Network Security Group](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm) OCIDs used to define network access for a deployment.
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// Deployment Data for an OggDeployment
        /// </summary>
        public readonly Outputs.GetDeploymentOggDataResult OggData;
        /// <summary>
        /// The private IP address in the customer's VCN representing the access point for the associated endpoint service in the GoldenGate service VCN.
        /// </summary>
        public readonly string PrivateIpAddress;
        /// <summary>
        /// The public IP address representing the access point for the Deployment.
        /// </summary>
        public readonly string PublicIpAddress;
        /// <summary>
        /// Possible lifecycle states.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet being referenced.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDeploymentResult(
            string compartmentId,

            int cpuCoreCount,

            ImmutableDictionary<string, object> definedTags,

            string deploymentBackupId,

            string deploymentId,

            string deploymentType,

            string deploymentUrl,

            string description,

            string displayName,

            string fqdn,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isAutoScalingEnabled,

            bool isHealthy,

            bool isLatestVersion,

            bool isPublic,

            string licenseModel,

            string lifecycleDetails,

            ImmutableArray<string> nsgIds,

            Outputs.GetDeploymentOggDataResult oggData,

            string privateIpAddress,

            string publicIpAddress,

            string state,

            string subnetId,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            CpuCoreCount = cpuCoreCount;
            DefinedTags = definedTags;
            DeploymentBackupId = deploymentBackupId;
            DeploymentId = deploymentId;
            DeploymentType = deploymentType;
            DeploymentUrl = deploymentUrl;
            Description = description;
            DisplayName = displayName;
            Fqdn = fqdn;
            FreeformTags = freeformTags;
            Id = id;
            IsAutoScalingEnabled = isAutoScalingEnabled;
            IsHealthy = isHealthy;
            IsLatestVersion = isLatestVersion;
            IsPublic = isPublic;
            LicenseModel = licenseModel;
            LifecycleDetails = lifecycleDetails;
            NsgIds = nsgIds;
            OggData = oggData;
            PrivateIpAddress = privateIpAddress;
            PublicIpAddress = publicIpAddress;
            State = state;
            SubnetId = subnetId;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
