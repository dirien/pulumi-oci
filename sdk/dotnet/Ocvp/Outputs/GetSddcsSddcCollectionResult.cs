// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp.Outputs
{

    [OutputType]
    public sealed class GetSddcsSddcCollectionResult
    {
        /// <summary>
        /// The number of actual ESXi hosts in the SDDC on the cloud. This attribute will be different when esxi Host is added to an existing SDDC.
        /// </summary>
        public readonly int ActualEsxiHostsCount;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The name of the availability domain that the Compute instances are running in.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string ComputeAvailabilityDomain;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The number of ESXi hosts in the SDDC.
        /// </summary>
        public readonly int EsxiHostsCount;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        public readonly string HcxAction;
        /// <summary>
        /// The FQDN for HCX Manager.  Example: `hcx-my-sddc.sddc.us-phoenix-1.oraclecloud.com`
        /// </summary>
        public readonly string HcxFqdn;
        /// <summary>
        /// The SDDC includes an administrator username and initial password for HCX Manager. Make sure to change this initial HCX Manager password to a different value.
        /// </summary>
        public readonly string HcxInitialPassword;
        /// <summary>
        /// The activation key to use on the on-premises HCX Enterprise appliance you site pair with HCX Manager in your VMware Solution. Your implementation might need more than one activation key. To obtain additional keys, contact Oracle Support.
        /// </summary>
        public readonly string HcxOnPremKey;
        /// <summary>
        /// The activation licenses to use on the on-premises HCX Enterprise appliance you site pair with HCX Manager in your VMware Solution.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSddcsSddcCollectionHcxOnPremLicenseResult> HcxOnPremLicenses;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PrivateIp` object that is the virtual IP (VIP) for HCX Manager. For information about `PrivateIp` objects, see the Core Services API.
        /// </summary>
        public readonly string HcxPrivateIpId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the HCX component of the VMware environment.
        /// </summary>
        public readonly string HcxVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Billing option selected during SDDC creation. Oracle Cloud Infrastructure VMware Solution supports the following billing interval SKUs: HOUR, MONTH, ONE_YEAR, and THREE_YEARS. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
        /// </summary>
        public readonly string InitialSku;
        /// <summary>
        /// A prefix used in the name of each ESXi host and Compute instance in the SDDC. If this isn't set, the SDDC's `displayName` is used as the prefix.
        /// </summary>
        public readonly string InstanceDisplayNamePrefix;
        /// <summary>
        /// Indicates whether HCX is enabled for this SDDC.
        /// </summary>
        public readonly bool IsHcxEnabled;
        /// <summary>
        /// Indicates whether HCX Enterprise is enabled for this SDDC.
        /// </summary>
        public readonly bool IsHcxEnterpriseEnabled;
        /// <summary>
        /// Indicates whether SDDC is pending downgrade from HCX Enterprise to HCX Advanced.
        /// </summary>
        public readonly bool IsHcxPendingDowngrade;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX Edge Uplink 1 component of the VMware environment.
        /// </summary>
        public readonly string NsxEdgeUplink1vlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX Edge Uplink 2 component of the VMware environment.
        /// </summary>
        public readonly string NsxEdgeUplink2vlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PrivateIp` object that is the virtual IP (VIP) for the NSX Edge Uplink. Use this OCID as the route target for route table rules when setting up connectivity between the SDDC and other networks. For information about `PrivateIp` objects, see the Core Services API.
        /// </summary>
        public readonly string NsxEdgeUplinkIpId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX Edge VTEP component of the VMware environment.
        /// </summary>
        public readonly string NsxEdgeVtepVlanId;
        /// <summary>
        /// The FQDN for NSX Manager.  Example: `nsx-my-sddc.sddc.us-phoenix-1.oraclecloud.com`
        /// </summary>
        public readonly string NsxManagerFqdn;
        /// <summary>
        /// The SDDC includes an administrator username and initial password for NSX Manager. Make sure to change this initial NSX Manager password to a different value.
        /// </summary>
        public readonly string NsxManagerInitialPassword;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PrivateIp` object that is the virtual IP (VIP) for NSX Manager. For information about `PrivateIp` objects, see the Core Services API.
        /// </summary>
        public readonly string NsxManagerPrivateIpId;
        /// <summary>
        /// The SDDC includes an administrator username and initial password for NSX Manager. You can change this initial username to a different value in NSX Manager.
        /// </summary>
        public readonly string NsxManagerUsername;
        /// <summary>
        /// The VMware NSX overlay workload segment to host your application. Connect to workload portgroup in vCenter to access this overlay segment.
        /// </summary>
        public readonly string NsxOverlaySegmentName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX VTEP component of the VMware environment.
        /// </summary>
        public readonly string NsxVtepVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet used to provision the SDDC.
        /// </summary>
        public readonly string ProvisioningSubnetId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the Provisioning component of the VMware environment.
        /// </summary>
        public readonly string ProvisioningVlanId;
        public readonly bool RefreshHcxLicenseStatus;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vSphere Replication component of the VMware environment.
        /// </summary>
        public readonly string ReplicationVlanId;
        public readonly ImmutableArray<string> ReservingHcxOnPremiseLicenseKeys;
        /// <summary>
        /// One or more public SSH keys to be included in the `~/.ssh/authorized_keys` file for the default user on each ESXi host. Use a newline character to separate multiple keys. The SSH keys must be in the format required for the `authorized_keys` file.
        /// </summary>
        public readonly string SshAuthorizedKeys;
        /// <summary>
        /// The lifecycle state of the resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the SDDC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time current HCX Enterprise billing cycle ends, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeHcxBillingCycleEnd;
        /// <summary>
        /// The date and time the SDDC's HCX on-premise license status was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeHcxLicenseStatusUpdated;
        /// <summary>
        /// The date and time the SDDC was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The FQDN for vCenter.  Example: `vcenter-my-sddc.sddc.us-phoenix-1.oraclecloud.com`
        /// </summary>
        public readonly string VcenterFqdn;
        /// <summary>
        /// The SDDC includes an administrator username and initial password for vCenter. Make sure to change this initial vCenter password to a different value.
        /// </summary>
        public readonly string VcenterInitialPassword;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PrivateIp` object that is the virtual IP (VIP) for vCenter. For information about `PrivateIp` objects, see the Core Services API.
        /// </summary>
        public readonly string VcenterPrivateIpId;
        /// <summary>
        /// The SDDC includes an administrator username and initial password for vCenter. You can change this initial username to a different value in vCenter.
        /// </summary>
        public readonly string VcenterUsername;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vMotion component of the VMware environment.
        /// </summary>
        public readonly string VmotionVlanId;
        /// <summary>
        /// In general, this is a specific version of bundled VMware software supported by Oracle Cloud VMware Solution (see [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions)).
        /// </summary>
        public readonly string VmwareSoftwareVersion;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vSAN component of the VMware environment.
        /// </summary>
        public readonly string VsanVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vSphere component of the VMware environment.
        /// </summary>
        public readonly string VsphereVlanId;
        /// <summary>
        /// The CIDR block for the IP addresses that VMware VMs in the SDDC use to run application workloads.
        /// </summary>
        public readonly string WorkloadNetworkCidr;

        [OutputConstructor]
        private GetSddcsSddcCollectionResult(
            int actualEsxiHostsCount,

            string compartmentId,

            string computeAvailabilityDomain,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            int esxiHostsCount,

            ImmutableDictionary<string, object> freeformTags,

            string hcxAction,

            string hcxFqdn,

            string hcxInitialPassword,

            string hcxOnPremKey,

            ImmutableArray<Outputs.GetSddcsSddcCollectionHcxOnPremLicenseResult> hcxOnPremLicenses,

            string hcxPrivateIpId,

            string hcxVlanId,

            string id,

            string initialSku,

            string instanceDisplayNamePrefix,

            bool isHcxEnabled,

            bool isHcxEnterpriseEnabled,

            bool isHcxPendingDowngrade,

            string nsxEdgeUplink1vlanId,

            string nsxEdgeUplink2vlanId,

            string nsxEdgeUplinkIpId,

            string nsxEdgeVtepVlanId,

            string nsxManagerFqdn,

            string nsxManagerInitialPassword,

            string nsxManagerPrivateIpId,

            string nsxManagerUsername,

            string nsxOverlaySegmentName,

            string nsxVtepVlanId,

            string provisioningSubnetId,

            string provisioningVlanId,

            bool refreshHcxLicenseStatus,

            string replicationVlanId,

            ImmutableArray<string> reservingHcxOnPremiseLicenseKeys,

            string sshAuthorizedKeys,

            string state,

            string timeCreated,

            string timeHcxBillingCycleEnd,

            string timeHcxLicenseStatusUpdated,

            string timeUpdated,

            string vcenterFqdn,

            string vcenterInitialPassword,

            string vcenterPrivateIpId,

            string vcenterUsername,

            string vmotionVlanId,

            string vmwareSoftwareVersion,

            string vsanVlanId,

            string vsphereVlanId,

            string workloadNetworkCidr)
        {
            ActualEsxiHostsCount = actualEsxiHostsCount;
            CompartmentId = compartmentId;
            ComputeAvailabilityDomain = computeAvailabilityDomain;
            DefinedTags = definedTags;
            DisplayName = displayName;
            EsxiHostsCount = esxiHostsCount;
            FreeformTags = freeformTags;
            HcxAction = hcxAction;
            HcxFqdn = hcxFqdn;
            HcxInitialPassword = hcxInitialPassword;
            HcxOnPremKey = hcxOnPremKey;
            HcxOnPremLicenses = hcxOnPremLicenses;
            HcxPrivateIpId = hcxPrivateIpId;
            HcxVlanId = hcxVlanId;
            Id = id;
            InitialSku = initialSku;
            InstanceDisplayNamePrefix = instanceDisplayNamePrefix;
            IsHcxEnabled = isHcxEnabled;
            IsHcxEnterpriseEnabled = isHcxEnterpriseEnabled;
            IsHcxPendingDowngrade = isHcxPendingDowngrade;
            NsxEdgeUplink1vlanId = nsxEdgeUplink1vlanId;
            NsxEdgeUplink2vlanId = nsxEdgeUplink2vlanId;
            NsxEdgeUplinkIpId = nsxEdgeUplinkIpId;
            NsxEdgeVtepVlanId = nsxEdgeVtepVlanId;
            NsxManagerFqdn = nsxManagerFqdn;
            NsxManagerInitialPassword = nsxManagerInitialPassword;
            NsxManagerPrivateIpId = nsxManagerPrivateIpId;
            NsxManagerUsername = nsxManagerUsername;
            NsxOverlaySegmentName = nsxOverlaySegmentName;
            NsxVtepVlanId = nsxVtepVlanId;
            ProvisioningSubnetId = provisioningSubnetId;
            ProvisioningVlanId = provisioningVlanId;
            RefreshHcxLicenseStatus = refreshHcxLicenseStatus;
            ReplicationVlanId = replicationVlanId;
            ReservingHcxOnPremiseLicenseKeys = reservingHcxOnPremiseLicenseKeys;
            SshAuthorizedKeys = sshAuthorizedKeys;
            State = state;
            TimeCreated = timeCreated;
            TimeHcxBillingCycleEnd = timeHcxBillingCycleEnd;
            TimeHcxLicenseStatusUpdated = timeHcxLicenseStatusUpdated;
            TimeUpdated = timeUpdated;
            VcenterFqdn = vcenterFqdn;
            VcenterInitialPassword = vcenterInitialPassword;
            VcenterPrivateIpId = vcenterPrivateIpId;
            VcenterUsername = vcenterUsername;
            VmotionVlanId = vmotionVlanId;
            VmwareSoftwareVersion = vmwareSoftwareVersion;
            VsanVlanId = vsanVlanId;
            VsphereVlanId = vsphereVlanId;
            WorkloadNetworkCidr = workloadNetworkCidr;
        }
    }
}
