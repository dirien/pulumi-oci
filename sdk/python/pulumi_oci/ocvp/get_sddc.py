# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetSddcResult',
    'AwaitableGetSddcResult',
    'get_sddc',
]

@pulumi.output_type
class GetSddcResult:
    """
    A collection of values returned by getSddc.
    """
    def __init__(__self__, actual_esxi_hosts_count=None, compartment_id=None, compute_availability_domain=None, defined_tags=None, display_name=None, esxi_hosts_count=None, freeform_tags=None, hcx_action=None, hcx_fqdn=None, hcx_initial_password=None, hcx_on_prem_key=None, hcx_on_prem_licenses=None, hcx_private_ip_id=None, hcx_vlan_id=None, id=None, initial_sku=None, instance_display_name_prefix=None, is_hcx_enabled=None, is_hcx_enterprise_enabled=None, is_hcx_pending_downgrade=None, nsx_edge_uplink1vlan_id=None, nsx_edge_uplink2vlan_id=None, nsx_edge_uplink_ip_id=None, nsx_edge_vtep_vlan_id=None, nsx_manager_fqdn=None, nsx_manager_initial_password=None, nsx_manager_private_ip_id=None, nsx_manager_username=None, nsx_overlay_segment_name=None, nsx_vtep_vlan_id=None, provisioning_subnet_id=None, provisioning_vlan_id=None, refresh_hcx_license_status=None, replication_vlan_id=None, reserving_hcx_on_premise_license_keys=None, sddc_id=None, ssh_authorized_keys=None, state=None, time_created=None, time_hcx_billing_cycle_end=None, time_hcx_license_status_updated=None, time_updated=None, vcenter_fqdn=None, vcenter_initial_password=None, vcenter_private_ip_id=None, vcenter_username=None, vmotion_vlan_id=None, vmware_software_version=None, vsan_vlan_id=None, vsphere_vlan_id=None, workload_network_cidr=None):
        if actual_esxi_hosts_count and not isinstance(actual_esxi_hosts_count, int):
            raise TypeError("Expected argument 'actual_esxi_hosts_count' to be a int")
        pulumi.set(__self__, "actual_esxi_hosts_count", actual_esxi_hosts_count)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_availability_domain and not isinstance(compute_availability_domain, str):
            raise TypeError("Expected argument 'compute_availability_domain' to be a str")
        pulumi.set(__self__, "compute_availability_domain", compute_availability_domain)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if esxi_hosts_count and not isinstance(esxi_hosts_count, int):
            raise TypeError("Expected argument 'esxi_hosts_count' to be a int")
        pulumi.set(__self__, "esxi_hosts_count", esxi_hosts_count)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if hcx_action and not isinstance(hcx_action, str):
            raise TypeError("Expected argument 'hcx_action' to be a str")
        pulumi.set(__self__, "hcx_action", hcx_action)
        if hcx_fqdn and not isinstance(hcx_fqdn, str):
            raise TypeError("Expected argument 'hcx_fqdn' to be a str")
        pulumi.set(__self__, "hcx_fqdn", hcx_fqdn)
        if hcx_initial_password and not isinstance(hcx_initial_password, str):
            raise TypeError("Expected argument 'hcx_initial_password' to be a str")
        pulumi.set(__self__, "hcx_initial_password", hcx_initial_password)
        if hcx_on_prem_key and not isinstance(hcx_on_prem_key, str):
            raise TypeError("Expected argument 'hcx_on_prem_key' to be a str")
        pulumi.set(__self__, "hcx_on_prem_key", hcx_on_prem_key)
        if hcx_on_prem_licenses and not isinstance(hcx_on_prem_licenses, list):
            raise TypeError("Expected argument 'hcx_on_prem_licenses' to be a list")
        pulumi.set(__self__, "hcx_on_prem_licenses", hcx_on_prem_licenses)
        if hcx_private_ip_id and not isinstance(hcx_private_ip_id, str):
            raise TypeError("Expected argument 'hcx_private_ip_id' to be a str")
        pulumi.set(__self__, "hcx_private_ip_id", hcx_private_ip_id)
        if hcx_vlan_id and not isinstance(hcx_vlan_id, str):
            raise TypeError("Expected argument 'hcx_vlan_id' to be a str")
        pulumi.set(__self__, "hcx_vlan_id", hcx_vlan_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if initial_sku and not isinstance(initial_sku, str):
            raise TypeError("Expected argument 'initial_sku' to be a str")
        pulumi.set(__self__, "initial_sku", initial_sku)
        if instance_display_name_prefix and not isinstance(instance_display_name_prefix, str):
            raise TypeError("Expected argument 'instance_display_name_prefix' to be a str")
        pulumi.set(__self__, "instance_display_name_prefix", instance_display_name_prefix)
        if is_hcx_enabled and not isinstance(is_hcx_enabled, bool):
            raise TypeError("Expected argument 'is_hcx_enabled' to be a bool")
        pulumi.set(__self__, "is_hcx_enabled", is_hcx_enabled)
        if is_hcx_enterprise_enabled and not isinstance(is_hcx_enterprise_enabled, bool):
            raise TypeError("Expected argument 'is_hcx_enterprise_enabled' to be a bool")
        pulumi.set(__self__, "is_hcx_enterprise_enabled", is_hcx_enterprise_enabled)
        if is_hcx_pending_downgrade and not isinstance(is_hcx_pending_downgrade, bool):
            raise TypeError("Expected argument 'is_hcx_pending_downgrade' to be a bool")
        pulumi.set(__self__, "is_hcx_pending_downgrade", is_hcx_pending_downgrade)
        if nsx_edge_uplink1vlan_id and not isinstance(nsx_edge_uplink1vlan_id, str):
            raise TypeError("Expected argument 'nsx_edge_uplink1vlan_id' to be a str")
        pulumi.set(__self__, "nsx_edge_uplink1vlan_id", nsx_edge_uplink1vlan_id)
        if nsx_edge_uplink2vlan_id and not isinstance(nsx_edge_uplink2vlan_id, str):
            raise TypeError("Expected argument 'nsx_edge_uplink2vlan_id' to be a str")
        pulumi.set(__self__, "nsx_edge_uplink2vlan_id", nsx_edge_uplink2vlan_id)
        if nsx_edge_uplink_ip_id and not isinstance(nsx_edge_uplink_ip_id, str):
            raise TypeError("Expected argument 'nsx_edge_uplink_ip_id' to be a str")
        pulumi.set(__self__, "nsx_edge_uplink_ip_id", nsx_edge_uplink_ip_id)
        if nsx_edge_vtep_vlan_id and not isinstance(nsx_edge_vtep_vlan_id, str):
            raise TypeError("Expected argument 'nsx_edge_vtep_vlan_id' to be a str")
        pulumi.set(__self__, "nsx_edge_vtep_vlan_id", nsx_edge_vtep_vlan_id)
        if nsx_manager_fqdn and not isinstance(nsx_manager_fqdn, str):
            raise TypeError("Expected argument 'nsx_manager_fqdn' to be a str")
        pulumi.set(__self__, "nsx_manager_fqdn", nsx_manager_fqdn)
        if nsx_manager_initial_password and not isinstance(nsx_manager_initial_password, str):
            raise TypeError("Expected argument 'nsx_manager_initial_password' to be a str")
        pulumi.set(__self__, "nsx_manager_initial_password", nsx_manager_initial_password)
        if nsx_manager_private_ip_id and not isinstance(nsx_manager_private_ip_id, str):
            raise TypeError("Expected argument 'nsx_manager_private_ip_id' to be a str")
        pulumi.set(__self__, "nsx_manager_private_ip_id", nsx_manager_private_ip_id)
        if nsx_manager_username and not isinstance(nsx_manager_username, str):
            raise TypeError("Expected argument 'nsx_manager_username' to be a str")
        pulumi.set(__self__, "nsx_manager_username", nsx_manager_username)
        if nsx_overlay_segment_name and not isinstance(nsx_overlay_segment_name, str):
            raise TypeError("Expected argument 'nsx_overlay_segment_name' to be a str")
        pulumi.set(__self__, "nsx_overlay_segment_name", nsx_overlay_segment_name)
        if nsx_vtep_vlan_id and not isinstance(nsx_vtep_vlan_id, str):
            raise TypeError("Expected argument 'nsx_vtep_vlan_id' to be a str")
        pulumi.set(__self__, "nsx_vtep_vlan_id", nsx_vtep_vlan_id)
        if provisioning_subnet_id and not isinstance(provisioning_subnet_id, str):
            raise TypeError("Expected argument 'provisioning_subnet_id' to be a str")
        pulumi.set(__self__, "provisioning_subnet_id", provisioning_subnet_id)
        if provisioning_vlan_id and not isinstance(provisioning_vlan_id, str):
            raise TypeError("Expected argument 'provisioning_vlan_id' to be a str")
        pulumi.set(__self__, "provisioning_vlan_id", provisioning_vlan_id)
        if refresh_hcx_license_status and not isinstance(refresh_hcx_license_status, bool):
            raise TypeError("Expected argument 'refresh_hcx_license_status' to be a bool")
        pulumi.set(__self__, "refresh_hcx_license_status", refresh_hcx_license_status)
        if replication_vlan_id and not isinstance(replication_vlan_id, str):
            raise TypeError("Expected argument 'replication_vlan_id' to be a str")
        pulumi.set(__self__, "replication_vlan_id", replication_vlan_id)
        if reserving_hcx_on_premise_license_keys and not isinstance(reserving_hcx_on_premise_license_keys, list):
            raise TypeError("Expected argument 'reserving_hcx_on_premise_license_keys' to be a list")
        pulumi.set(__self__, "reserving_hcx_on_premise_license_keys", reserving_hcx_on_premise_license_keys)
        if sddc_id and not isinstance(sddc_id, str):
            raise TypeError("Expected argument 'sddc_id' to be a str")
        pulumi.set(__self__, "sddc_id", sddc_id)
        if ssh_authorized_keys and not isinstance(ssh_authorized_keys, str):
            raise TypeError("Expected argument 'ssh_authorized_keys' to be a str")
        pulumi.set(__self__, "ssh_authorized_keys", ssh_authorized_keys)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_hcx_billing_cycle_end and not isinstance(time_hcx_billing_cycle_end, str):
            raise TypeError("Expected argument 'time_hcx_billing_cycle_end' to be a str")
        pulumi.set(__self__, "time_hcx_billing_cycle_end", time_hcx_billing_cycle_end)
        if time_hcx_license_status_updated and not isinstance(time_hcx_license_status_updated, str):
            raise TypeError("Expected argument 'time_hcx_license_status_updated' to be a str")
        pulumi.set(__self__, "time_hcx_license_status_updated", time_hcx_license_status_updated)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if vcenter_fqdn and not isinstance(vcenter_fqdn, str):
            raise TypeError("Expected argument 'vcenter_fqdn' to be a str")
        pulumi.set(__self__, "vcenter_fqdn", vcenter_fqdn)
        if vcenter_initial_password and not isinstance(vcenter_initial_password, str):
            raise TypeError("Expected argument 'vcenter_initial_password' to be a str")
        pulumi.set(__self__, "vcenter_initial_password", vcenter_initial_password)
        if vcenter_private_ip_id and not isinstance(vcenter_private_ip_id, str):
            raise TypeError("Expected argument 'vcenter_private_ip_id' to be a str")
        pulumi.set(__self__, "vcenter_private_ip_id", vcenter_private_ip_id)
        if vcenter_username and not isinstance(vcenter_username, str):
            raise TypeError("Expected argument 'vcenter_username' to be a str")
        pulumi.set(__self__, "vcenter_username", vcenter_username)
        if vmotion_vlan_id and not isinstance(vmotion_vlan_id, str):
            raise TypeError("Expected argument 'vmotion_vlan_id' to be a str")
        pulumi.set(__self__, "vmotion_vlan_id", vmotion_vlan_id)
        if vmware_software_version and not isinstance(vmware_software_version, str):
            raise TypeError("Expected argument 'vmware_software_version' to be a str")
        pulumi.set(__self__, "vmware_software_version", vmware_software_version)
        if vsan_vlan_id and not isinstance(vsan_vlan_id, str):
            raise TypeError("Expected argument 'vsan_vlan_id' to be a str")
        pulumi.set(__self__, "vsan_vlan_id", vsan_vlan_id)
        if vsphere_vlan_id and not isinstance(vsphere_vlan_id, str):
            raise TypeError("Expected argument 'vsphere_vlan_id' to be a str")
        pulumi.set(__self__, "vsphere_vlan_id", vsphere_vlan_id)
        if workload_network_cidr and not isinstance(workload_network_cidr, str):
            raise TypeError("Expected argument 'workload_network_cidr' to be a str")
        pulumi.set(__self__, "workload_network_cidr", workload_network_cidr)

    @property
    @pulumi.getter(name="actualEsxiHostsCount")
    def actual_esxi_hosts_count(self) -> int:
        """
        The number of actual ESXi hosts in the SDDC on the cloud. This attribute will be different when esxi Host is added to an existing SDDC.
        """
        return pulumi.get(self, "actual_esxi_hosts_count")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the SDDC.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="computeAvailabilityDomain")
    def compute_availability_domain(self) -> str:
        """
        The availability domain the ESXi hosts are running in.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "compute_availability_domain")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A descriptive name for the SDDC. It must be unique, start with a letter, and contain only letters, digits, whitespaces, dashes and underscores. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="esxiHostsCount")
    def esxi_hosts_count(self) -> int:
        """
        The number of ESXi hosts in the SDDC.
        """
        return pulumi.get(self, "esxi_hosts_count")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="hcxAction")
    def hcx_action(self) -> str:
        return pulumi.get(self, "hcx_action")

    @property
    @pulumi.getter(name="hcxFqdn")
    def hcx_fqdn(self) -> str:
        """
        The FQDN for HCX Manager.  Example: `hcx-my-sddc.sddc.us-phoenix-1.oraclecloud.com`
        """
        return pulumi.get(self, "hcx_fqdn")

    @property
    @pulumi.getter(name="hcxInitialPassword")
    def hcx_initial_password(self) -> str:
        """
        The SDDC includes an administrator username and initial password for HCX Manager. Make sure to change this initial HCX Manager password to a different value.
        """
        return pulumi.get(self, "hcx_initial_password")

    @property
    @pulumi.getter(name="hcxOnPremKey")
    def hcx_on_prem_key(self) -> str:
        """
        The activation key to use on the on-premises HCX Enterprise appliance you site pair with HCX Manager in your VMware Solution. Your implementation might need more than one activation key. To obtain additional keys, contact Oracle Support.
        """
        return pulumi.get(self, "hcx_on_prem_key")

    @property
    @pulumi.getter(name="hcxOnPremLicenses")
    def hcx_on_prem_licenses(self) -> Sequence['outputs.GetSddcHcxOnPremLicenseResult']:
        """
        The activation licenses to use on the on-premises HCX Enterprise appliance you site pair with HCX Manager in your VMware Solution.
        """
        return pulumi.get(self, "hcx_on_prem_licenses")

    @property
    @pulumi.getter(name="hcxPrivateIpId")
    def hcx_private_ip_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PrivateIp` object that is the virtual IP (VIP) for HCX Manager. For information about `PrivateIp` objects, see the Core Services API.
        """
        return pulumi.get(self, "hcx_private_ip_id")

    @property
    @pulumi.getter(name="hcxVlanId")
    def hcx_vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the HCX component of the VMware environment.
        """
        return pulumi.get(self, "hcx_vlan_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="initialSku")
    def initial_sku(self) -> str:
        """
        Billing option selected during SDDC creation. Oracle Cloud Infrastructure VMware Solution supports the following billing interval SKUs: HOUR, MONTH, ONE_YEAR, and THREE_YEARS. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
        """
        return pulumi.get(self, "initial_sku")

    @property
    @pulumi.getter(name="instanceDisplayNamePrefix")
    def instance_display_name_prefix(self) -> str:
        """
        A prefix used in the name of each ESXi host and Compute instance in the SDDC. If this isn't set, the SDDC's `displayName` is used as the prefix.
        """
        return pulumi.get(self, "instance_display_name_prefix")

    @property
    @pulumi.getter(name="isHcxEnabled")
    def is_hcx_enabled(self) -> bool:
        """
        Indicates whether HCX is enabled for this SDDC.
        """
        return pulumi.get(self, "is_hcx_enabled")

    @property
    @pulumi.getter(name="isHcxEnterpriseEnabled")
    def is_hcx_enterprise_enabled(self) -> bool:
        """
        Indicates whether HCX Enterprise is enabled for this SDDC.
        """
        return pulumi.get(self, "is_hcx_enterprise_enabled")

    @property
    @pulumi.getter(name="isHcxPendingDowngrade")
    def is_hcx_pending_downgrade(self) -> bool:
        """
        Indicates whether SDDC is pending downgrade from HCX Enterprise to HCX Advanced.
        """
        return pulumi.get(self, "is_hcx_pending_downgrade")

    @property
    @pulumi.getter(name="nsxEdgeUplink1vlanId")
    def nsx_edge_uplink1vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX Edge Uplink 1 component of the VMware environment.
        """
        return pulumi.get(self, "nsx_edge_uplink1vlan_id")

    @property
    @pulumi.getter(name="nsxEdgeUplink2vlanId")
    def nsx_edge_uplink2vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX Edge Uplink 2 component of the VMware environment.
        """
        return pulumi.get(self, "nsx_edge_uplink2vlan_id")

    @property
    @pulumi.getter(name="nsxEdgeUplinkIpId")
    def nsx_edge_uplink_ip_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PrivateIp` object that is the virtual IP (VIP) for the NSX Edge Uplink. Use this OCID as the route target for route table rules when setting up connectivity between the SDDC and other networks. For information about `PrivateIp` objects, see the Core Services API.
        """
        return pulumi.get(self, "nsx_edge_uplink_ip_id")

    @property
    @pulumi.getter(name="nsxEdgeVtepVlanId")
    def nsx_edge_vtep_vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX Edge VTEP component of the VMware environment.
        """
        return pulumi.get(self, "nsx_edge_vtep_vlan_id")

    @property
    @pulumi.getter(name="nsxManagerFqdn")
    def nsx_manager_fqdn(self) -> str:
        """
        The FQDN for NSX Manager.  Example: `nsx-my-sddc.sddc.us-phoenix-1.oraclecloud.com`
        """
        return pulumi.get(self, "nsx_manager_fqdn")

    @property
    @pulumi.getter(name="nsxManagerInitialPassword")
    def nsx_manager_initial_password(self) -> str:
        """
        The SDDC includes an administrator username and initial password for NSX Manager. Make sure to change this initial NSX Manager password to a different value.
        """
        return pulumi.get(self, "nsx_manager_initial_password")

    @property
    @pulumi.getter(name="nsxManagerPrivateIpId")
    def nsx_manager_private_ip_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PrivateIp` object that is the virtual IP (VIP) for NSX Manager. For information about `PrivateIp` objects, see the Core Services API.
        """
        return pulumi.get(self, "nsx_manager_private_ip_id")

    @property
    @pulumi.getter(name="nsxManagerUsername")
    def nsx_manager_username(self) -> str:
        """
        The SDDC includes an administrator username and initial password for NSX Manager. You can change this initial username to a different value in NSX Manager.
        """
        return pulumi.get(self, "nsx_manager_username")

    @property
    @pulumi.getter(name="nsxOverlaySegmentName")
    def nsx_overlay_segment_name(self) -> str:
        """
        The VMware NSX overlay workload segment to host your application. Connect to workload portgroup in vCenter to access this overlay segment.
        """
        return pulumi.get(self, "nsx_overlay_segment_name")

    @property
    @pulumi.getter(name="nsxVtepVlanId")
    def nsx_vtep_vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX VTEP component of the VMware environment.
        """
        return pulumi.get(self, "nsx_vtep_vlan_id")

    @property
    @pulumi.getter(name="provisioningSubnetId")
    def provisioning_subnet_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet used to provision the SDDC.
        """
        return pulumi.get(self, "provisioning_subnet_id")

    @property
    @pulumi.getter(name="provisioningVlanId")
    def provisioning_vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the Provisioning component of the VMware environment.
        """
        return pulumi.get(self, "provisioning_vlan_id")

    @property
    @pulumi.getter(name="refreshHcxLicenseStatus")
    def refresh_hcx_license_status(self) -> bool:
        return pulumi.get(self, "refresh_hcx_license_status")

    @property
    @pulumi.getter(name="replicationVlanId")
    def replication_vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vSphere Replication component of the VMware environment.
        """
        return pulumi.get(self, "replication_vlan_id")

    @property
    @pulumi.getter(name="reservingHcxOnPremiseLicenseKeys")
    def reserving_hcx_on_premise_license_keys(self) -> Sequence[str]:
        return pulumi.get(self, "reserving_hcx_on_premise_license_keys")

    @property
    @pulumi.getter(name="sddcId")
    def sddc_id(self) -> str:
        return pulumi.get(self, "sddc_id")

    @property
    @pulumi.getter(name="sshAuthorizedKeys")
    def ssh_authorized_keys(self) -> str:
        """
        One or more public SSH keys to be included in the `~/.ssh/authorized_keys` file for the default user on each ESXi host. Use a newline character to separate multiple keys. The SSH keys must be in the format required for the `authorized_keys` file.
        """
        return pulumi.get(self, "ssh_authorized_keys")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the SDDC.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the SDDC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeHcxBillingCycleEnd")
    def time_hcx_billing_cycle_end(self) -> str:
        """
        The date and time current HCX Enterprise billing cycle ends, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_hcx_billing_cycle_end")

    @property
    @pulumi.getter(name="timeHcxLicenseStatusUpdated")
    def time_hcx_license_status_updated(self) -> str:
        """
        The date and time the SDDC's HCX on-premise license status was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_hcx_license_status_updated")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The date and time the SDDC was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="vcenterFqdn")
    def vcenter_fqdn(self) -> str:
        """
        The FQDN for vCenter.  Example: `vcenter-my-sddc.sddc.us-phoenix-1.oraclecloud.com`
        """
        return pulumi.get(self, "vcenter_fqdn")

    @property
    @pulumi.getter(name="vcenterInitialPassword")
    def vcenter_initial_password(self) -> str:
        """
        The SDDC includes an administrator username and initial password for vCenter. Make sure to change this initial vCenter password to a different value.
        """
        return pulumi.get(self, "vcenter_initial_password")

    @property
    @pulumi.getter(name="vcenterPrivateIpId")
    def vcenter_private_ip_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PrivateIp` object that is the virtual IP (VIP) for vCenter. For information about `PrivateIp` objects, see the Core Services API.
        """
        return pulumi.get(self, "vcenter_private_ip_id")

    @property
    @pulumi.getter(name="vcenterUsername")
    def vcenter_username(self) -> str:
        """
        The SDDC includes an administrator username and initial password for vCenter. You can change this initial username to a different value in vCenter.
        """
        return pulumi.get(self, "vcenter_username")

    @property
    @pulumi.getter(name="vmotionVlanId")
    def vmotion_vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vMotion component of the VMware environment.
        """
        return pulumi.get(self, "vmotion_vlan_id")

    @property
    @pulumi.getter(name="vmwareSoftwareVersion")
    def vmware_software_version(self) -> str:
        """
        In general, this is a specific version of bundled VMware software supported by Oracle Cloud VMware Solution (see [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions)).
        """
        return pulumi.get(self, "vmware_software_version")

    @property
    @pulumi.getter(name="vsanVlanId")
    def vsan_vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vSAN component of the VMware environment.
        """
        return pulumi.get(self, "vsan_vlan_id")

    @property
    @pulumi.getter(name="vsphereVlanId")
    def vsphere_vlan_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vSphere component of the VMware environment.
        """
        return pulumi.get(self, "vsphere_vlan_id")

    @property
    @pulumi.getter(name="workloadNetworkCidr")
    def workload_network_cidr(self) -> str:
        """
        The CIDR block for the IP addresses that VMware VMs in the SDDC use to run application workloads.
        """
        return pulumi.get(self, "workload_network_cidr")


class AwaitableGetSddcResult(GetSddcResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSddcResult(
            actual_esxi_hosts_count=self.actual_esxi_hosts_count,
            compartment_id=self.compartment_id,
            compute_availability_domain=self.compute_availability_domain,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            esxi_hosts_count=self.esxi_hosts_count,
            freeform_tags=self.freeform_tags,
            hcx_action=self.hcx_action,
            hcx_fqdn=self.hcx_fqdn,
            hcx_initial_password=self.hcx_initial_password,
            hcx_on_prem_key=self.hcx_on_prem_key,
            hcx_on_prem_licenses=self.hcx_on_prem_licenses,
            hcx_private_ip_id=self.hcx_private_ip_id,
            hcx_vlan_id=self.hcx_vlan_id,
            id=self.id,
            initial_sku=self.initial_sku,
            instance_display_name_prefix=self.instance_display_name_prefix,
            is_hcx_enabled=self.is_hcx_enabled,
            is_hcx_enterprise_enabled=self.is_hcx_enterprise_enabled,
            is_hcx_pending_downgrade=self.is_hcx_pending_downgrade,
            nsx_edge_uplink1vlan_id=self.nsx_edge_uplink1vlan_id,
            nsx_edge_uplink2vlan_id=self.nsx_edge_uplink2vlan_id,
            nsx_edge_uplink_ip_id=self.nsx_edge_uplink_ip_id,
            nsx_edge_vtep_vlan_id=self.nsx_edge_vtep_vlan_id,
            nsx_manager_fqdn=self.nsx_manager_fqdn,
            nsx_manager_initial_password=self.nsx_manager_initial_password,
            nsx_manager_private_ip_id=self.nsx_manager_private_ip_id,
            nsx_manager_username=self.nsx_manager_username,
            nsx_overlay_segment_name=self.nsx_overlay_segment_name,
            nsx_vtep_vlan_id=self.nsx_vtep_vlan_id,
            provisioning_subnet_id=self.provisioning_subnet_id,
            provisioning_vlan_id=self.provisioning_vlan_id,
            refresh_hcx_license_status=self.refresh_hcx_license_status,
            replication_vlan_id=self.replication_vlan_id,
            reserving_hcx_on_premise_license_keys=self.reserving_hcx_on_premise_license_keys,
            sddc_id=self.sddc_id,
            ssh_authorized_keys=self.ssh_authorized_keys,
            state=self.state,
            time_created=self.time_created,
            time_hcx_billing_cycle_end=self.time_hcx_billing_cycle_end,
            time_hcx_license_status_updated=self.time_hcx_license_status_updated,
            time_updated=self.time_updated,
            vcenter_fqdn=self.vcenter_fqdn,
            vcenter_initial_password=self.vcenter_initial_password,
            vcenter_private_ip_id=self.vcenter_private_ip_id,
            vcenter_username=self.vcenter_username,
            vmotion_vlan_id=self.vmotion_vlan_id,
            vmware_software_version=self.vmware_software_version,
            vsan_vlan_id=self.vsan_vlan_id,
            vsphere_vlan_id=self.vsphere_vlan_id,
            workload_network_cidr=self.workload_network_cidr)


def get_sddc(sddc_id: Optional[str] = None,
             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSddcResult:
    """
    This data source provides details about a specific Sddc resource in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.

    Gets the specified SDDC's information.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_sddc = oci.ocvp.get_sddc(sddc_id=oci_ocvp_sddc["test_sddc"]["id"])
    ```


    :param str sddc_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
    """
    __args__ = dict()
    __args__['sddcId'] = sddc_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:ocvp/getSddc:getSddc', __args__, opts=opts, typ=GetSddcResult).value

    return AwaitableGetSddcResult(
        actual_esxi_hosts_count=__ret__.actual_esxi_hosts_count,
        compartment_id=__ret__.compartment_id,
        compute_availability_domain=__ret__.compute_availability_domain,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        esxi_hosts_count=__ret__.esxi_hosts_count,
        freeform_tags=__ret__.freeform_tags,
        hcx_action=__ret__.hcx_action,
        hcx_fqdn=__ret__.hcx_fqdn,
        hcx_initial_password=__ret__.hcx_initial_password,
        hcx_on_prem_key=__ret__.hcx_on_prem_key,
        hcx_on_prem_licenses=__ret__.hcx_on_prem_licenses,
        hcx_private_ip_id=__ret__.hcx_private_ip_id,
        hcx_vlan_id=__ret__.hcx_vlan_id,
        id=__ret__.id,
        initial_sku=__ret__.initial_sku,
        instance_display_name_prefix=__ret__.instance_display_name_prefix,
        is_hcx_enabled=__ret__.is_hcx_enabled,
        is_hcx_enterprise_enabled=__ret__.is_hcx_enterprise_enabled,
        is_hcx_pending_downgrade=__ret__.is_hcx_pending_downgrade,
        nsx_edge_uplink1vlan_id=__ret__.nsx_edge_uplink1vlan_id,
        nsx_edge_uplink2vlan_id=__ret__.nsx_edge_uplink2vlan_id,
        nsx_edge_uplink_ip_id=__ret__.nsx_edge_uplink_ip_id,
        nsx_edge_vtep_vlan_id=__ret__.nsx_edge_vtep_vlan_id,
        nsx_manager_fqdn=__ret__.nsx_manager_fqdn,
        nsx_manager_initial_password=__ret__.nsx_manager_initial_password,
        nsx_manager_private_ip_id=__ret__.nsx_manager_private_ip_id,
        nsx_manager_username=__ret__.nsx_manager_username,
        nsx_overlay_segment_name=__ret__.nsx_overlay_segment_name,
        nsx_vtep_vlan_id=__ret__.nsx_vtep_vlan_id,
        provisioning_subnet_id=__ret__.provisioning_subnet_id,
        provisioning_vlan_id=__ret__.provisioning_vlan_id,
        refresh_hcx_license_status=__ret__.refresh_hcx_license_status,
        replication_vlan_id=__ret__.replication_vlan_id,
        reserving_hcx_on_premise_license_keys=__ret__.reserving_hcx_on_premise_license_keys,
        sddc_id=__ret__.sddc_id,
        ssh_authorized_keys=__ret__.ssh_authorized_keys,
        state=__ret__.state,
        time_created=__ret__.time_created,
        time_hcx_billing_cycle_end=__ret__.time_hcx_billing_cycle_end,
        time_hcx_license_status_updated=__ret__.time_hcx_license_status_updated,
        time_updated=__ret__.time_updated,
        vcenter_fqdn=__ret__.vcenter_fqdn,
        vcenter_initial_password=__ret__.vcenter_initial_password,
        vcenter_private_ip_id=__ret__.vcenter_private_ip_id,
        vcenter_username=__ret__.vcenter_username,
        vmotion_vlan_id=__ret__.vmotion_vlan_id,
        vmware_software_version=__ret__.vmware_software_version,
        vsan_vlan_id=__ret__.vsan_vlan_id,
        vsphere_vlan_id=__ret__.vsphere_vlan_id,
        workload_network_cidr=__ret__.workload_network_cidr)
