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
    'AnalyticsInstanceCapacity',
    'AnalyticsInstanceNetworkEndpointDetails',
    'AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn',
    'AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone',
    'GetAnalyticsInstanceCapacityResult',
    'GetAnalyticsInstanceNetworkEndpointDetailsResult',
    'GetAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnResult',
    'GetAnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneResult',
    'GetAnalyticsInstancesAnalyticsInstanceResult',
    'GetAnalyticsInstancesAnalyticsInstanceCapacityResult',
    'GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsResult',
    'GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnResult',
    'GetAnalyticsInstancesFilterResult',
]

@pulumi.output_type
class AnalyticsInstanceCapacity(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "capacityType":
            suggest = "capacity_type"
        elif key == "capacityValue":
            suggest = "capacity_value"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in AnalyticsInstanceCapacity. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        AnalyticsInstanceCapacity.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        AnalyticsInstanceCapacity.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 capacity_type: str,
                 capacity_value: int):
        """
        :param str capacity_type: The capacity model to use.
        :param int capacity_value: (Updatable) The capacity value selected (OLPU count, number of users, ...etc...). This parameter affects the number of CPUs, amount of memory or other resources allocated to the instance.
        """
        pulumi.set(__self__, "capacity_type", capacity_type)
        pulumi.set(__self__, "capacity_value", capacity_value)

    @property
    @pulumi.getter(name="capacityType")
    def capacity_type(self) -> str:
        """
        The capacity model to use.
        """
        return pulumi.get(self, "capacity_type")

    @property
    @pulumi.getter(name="capacityValue")
    def capacity_value(self) -> int:
        """
        (Updatable) The capacity value selected (OLPU count, number of users, ...etc...). This parameter affects the number of CPUs, amount of memory or other resources allocated to the instance.
        """
        return pulumi.get(self, "capacity_value")


@pulumi.output_type
class AnalyticsInstanceNetworkEndpointDetails(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "networkEndpointType":
            suggest = "network_endpoint_type"
        elif key == "subnetId":
            suggest = "subnet_id"
        elif key == "vcnId":
            suggest = "vcn_id"
        elif key == "whitelistedIps":
            suggest = "whitelisted_ips"
        elif key == "whitelistedVcns":
            suggest = "whitelisted_vcns"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in AnalyticsInstanceNetworkEndpointDetails. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        AnalyticsInstanceNetworkEndpointDetails.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        AnalyticsInstanceNetworkEndpointDetails.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 network_endpoint_type: str,
                 subnet_id: Optional[str] = None,
                 vcn_id: Optional[str] = None,
                 whitelisted_ips: Optional[Sequence[str]] = None,
                 whitelisted_vcns: Optional[Sequence['outputs.AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn']] = None):
        """
        :param str network_endpoint_type: The type of network endpoint.
        :param str subnet_id: The subnet OCID for the private endpoint.
        :param str vcn_id: The VCN OCID for the private endpoint.
        :param Sequence[str] whitelisted_ips: Source IP addresses or IP address ranges igress rules.
        :param Sequence['AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnArgs'] whitelisted_vcns: Virtual Cloud Networks allowed to access this network endpoint.
        """
        pulumi.set(__self__, "network_endpoint_type", network_endpoint_type)
        if subnet_id is not None:
            pulumi.set(__self__, "subnet_id", subnet_id)
        if vcn_id is not None:
            pulumi.set(__self__, "vcn_id", vcn_id)
        if whitelisted_ips is not None:
            pulumi.set(__self__, "whitelisted_ips", whitelisted_ips)
        if whitelisted_vcns is not None:
            pulumi.set(__self__, "whitelisted_vcns", whitelisted_vcns)

    @property
    @pulumi.getter(name="networkEndpointType")
    def network_endpoint_type(self) -> str:
        """
        The type of network endpoint.
        """
        return pulumi.get(self, "network_endpoint_type")

    @property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> Optional[str]:
        """
        The subnet OCID for the private endpoint.
        """
        return pulumi.get(self, "subnet_id")

    @property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> Optional[str]:
        """
        The VCN OCID for the private endpoint.
        """
        return pulumi.get(self, "vcn_id")

    @property
    @pulumi.getter(name="whitelistedIps")
    def whitelisted_ips(self) -> Optional[Sequence[str]]:
        """
        Source IP addresses or IP address ranges igress rules.
        """
        return pulumi.get(self, "whitelisted_ips")

    @property
    @pulumi.getter(name="whitelistedVcns")
    def whitelisted_vcns(self) -> Optional[Sequence['outputs.AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn']]:
        """
        Virtual Cloud Networks allowed to access this network endpoint.
        """
        return pulumi.get(self, "whitelisted_vcns")


@pulumi.output_type
class AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "whitelistedIps":
            suggest = "whitelisted_ips"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 id: Optional[str] = None,
                 whitelisted_ips: Optional[Sequence[str]] = None):
        """
        :param str id: The Virtual Cloud Network OCID.
        :param Sequence[str] whitelisted_ips: Source IP addresses or IP address ranges igress rules.
        """
        if id is not None:
            pulumi.set(__self__, "id", id)
        if whitelisted_ips is not None:
            pulumi.set(__self__, "whitelisted_ips", whitelisted_ips)

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="whitelistedIps")
    def whitelisted_ips(self) -> Optional[Sequence[str]]:
        """
        Source IP addresses or IP address ranges igress rules.
        """
        return pulumi.get(self, "whitelisted_ips")


@pulumi.output_type
class AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "dnsZone":
            suggest = "dns_zone"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 dns_zone: str,
                 description: Optional[str] = None):
        """
        :param str dns_zone: (Updatable) Private Source DNS Zone. Ex: example-vcn.oraclevcn.com, corp.example.com.
        :param str description: (Updatable) Description of private source dns zone.
        """
        pulumi.set(__self__, "dns_zone", dns_zone)
        if description is not None:
            pulumi.set(__self__, "description", description)

    @property
    @pulumi.getter(name="dnsZone")
    def dns_zone(self) -> str:
        """
        (Updatable) Private Source DNS Zone. Ex: example-vcn.oraclevcn.com, corp.example.com.
        """
        return pulumi.get(self, "dns_zone")

    @property
    @pulumi.getter
    def description(self) -> Optional[str]:
        """
        (Updatable) Description of private source dns zone.
        """
        return pulumi.get(self, "description")


@pulumi.output_type
class GetAnalyticsInstanceCapacityResult(dict):
    def __init__(__self__, *,
                 capacity_type: str,
                 capacity_value: int):
        """
        :param str capacity_type: The capacity model to use.
        :param int capacity_value: The capacity value selected (OLPU count, number of users, ...etc...). This parameter affects the number of CPUs, amount of memory or other resources allocated to the instance.
        """
        pulumi.set(__self__, "capacity_type", capacity_type)
        pulumi.set(__self__, "capacity_value", capacity_value)

    @property
    @pulumi.getter(name="capacityType")
    def capacity_type(self) -> str:
        """
        The capacity model to use.
        """
        return pulumi.get(self, "capacity_type")

    @property
    @pulumi.getter(name="capacityValue")
    def capacity_value(self) -> int:
        """
        The capacity value selected (OLPU count, number of users, ...etc...). This parameter affects the number of CPUs, amount of memory or other resources allocated to the instance.
        """
        return pulumi.get(self, "capacity_value")


@pulumi.output_type
class GetAnalyticsInstanceNetworkEndpointDetailsResult(dict):
    def __init__(__self__, *,
                 network_endpoint_type: str,
                 subnet_id: str,
                 vcn_id: str,
                 whitelisted_ips: Sequence[str],
                 whitelisted_vcns: Sequence['outputs.GetAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnResult']):
        """
        :param str network_endpoint_type: The type of network endpoint.
        :param str subnet_id: OCID of the customer subnet connected to private access channel.
        :param str vcn_id: OCID of the customer VCN peered with private access channel.
        :param Sequence[str] whitelisted_ips: Source IP addresses or IP address ranges igress rules.
        :param Sequence['GetAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnArgs'] whitelisted_vcns: Virtual Cloud Networks allowed to access this network endpoint.
        """
        pulumi.set(__self__, "network_endpoint_type", network_endpoint_type)
        pulumi.set(__self__, "subnet_id", subnet_id)
        pulumi.set(__self__, "vcn_id", vcn_id)
        pulumi.set(__self__, "whitelisted_ips", whitelisted_ips)
        pulumi.set(__self__, "whitelisted_vcns", whitelisted_vcns)

    @property
    @pulumi.getter(name="networkEndpointType")
    def network_endpoint_type(self) -> str:
        """
        The type of network endpoint.
        """
        return pulumi.get(self, "network_endpoint_type")

    @property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> str:
        """
        OCID of the customer subnet connected to private access channel.
        """
        return pulumi.get(self, "subnet_id")

    @property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> str:
        """
        OCID of the customer VCN peered with private access channel.
        """
        return pulumi.get(self, "vcn_id")

    @property
    @pulumi.getter(name="whitelistedIps")
    def whitelisted_ips(self) -> Sequence[str]:
        """
        Source IP addresses or IP address ranges igress rules.
        """
        return pulumi.get(self, "whitelisted_ips")

    @property
    @pulumi.getter(name="whitelistedVcns")
    def whitelisted_vcns(self) -> Sequence['outputs.GetAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnResult']:
        """
        Virtual Cloud Networks allowed to access this network endpoint.
        """
        return pulumi.get(self, "whitelisted_vcns")


@pulumi.output_type
class GetAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnResult(dict):
    def __init__(__self__, *,
                 id: str,
                 whitelisted_ips: Sequence[str]):
        """
        :param str id: The Virtual Cloud Network OCID.
        :param Sequence[str] whitelisted_ips: Source IP addresses or IP address ranges igress rules.
        """
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "whitelisted_ips", whitelisted_ips)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="whitelistedIps")
    def whitelisted_ips(self) -> Sequence[str]:
        """
        Source IP addresses or IP address ranges igress rules.
        """
        return pulumi.get(self, "whitelisted_ips")


@pulumi.output_type
class GetAnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneResult(dict):
    def __init__(__self__, *,
                 description: str,
                 dns_zone: str):
        """
        :param str description: Description of private source dns zone.
        :param str dns_zone: Private Source DNS Zone. Ex: example-vcn.oraclevcn.com, corp.example.com.
        """
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "dns_zone", dns_zone)

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description of private source dns zone.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="dnsZone")
    def dns_zone(self) -> str:
        """
        Private Source DNS Zone. Ex: example-vcn.oraclevcn.com, corp.example.com.
        """
        return pulumi.get(self, "dns_zone")


@pulumi.output_type
class GetAnalyticsInstancesAnalyticsInstanceResult(dict):
    def __init__(__self__, *,
                 capacity: 'outputs.GetAnalyticsInstancesAnalyticsInstanceCapacityResult',
                 compartment_id: str,
                 defined_tags: Mapping[str, Any],
                 description: str,
                 email_notification: str,
                 feature_set: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 idcs_access_token: str,
                 license_type: str,
                 name: str,
                 network_endpoint_details: 'outputs.GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsResult',
                 private_access_channels: Mapping[str, Any],
                 service_url: str,
                 state: str,
                 time_created: str,
                 time_updated: str,
                 vanity_url_details: Mapping[str, Any]):
        """
        :param 'GetAnalyticsInstancesAnalyticsInstanceCapacityArgs' capacity: Service instance capacity metadata (e.g.: OLPU count, number of users, ...etc...).
        :param str compartment_id: The OCID of the compartment.
        :param Mapping[str, Any] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param str description: Description of the vanity url.
        :param str email_notification: Email address receiving notifications.
        :param str feature_set: A filter to only return resources matching the feature set. Values are case-insensitive.
        :param Mapping[str, Any] freeform_tags: Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param str id: The Virtual Cloud Network OCID.
        :param str license_type: The license used for the service.
        :param str name: A filter to return only resources that match the given name exactly.
        :param 'GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsArgs' network_endpoint_details: Base representation of a network endpoint.
        :param Mapping[str, Any] private_access_channels: Map of PrivateAccessChannel unique identifier key as KEY and PrivateAccessChannel Object as VALUE.
        :param str service_url: URL of the Analytics service.
        :param str state: A filter to only return resources matching the lifecycle state. The state value is case-insensitive.
        :param str time_created: The date and time the instance was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        :param str time_updated: The date and time the instance was last updated (in the format defined by RFC3339). This timestamp represents updates made through this API. External events do not influence it.
        :param Mapping[str, Any] vanity_url_details: Map of VanityUrl unique identifier key as KEY and VanityUrl Object as VALUE.
        """
        pulumi.set(__self__, "capacity", capacity)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "email_notification", email_notification)
        pulumi.set(__self__, "feature_set", feature_set)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "idcs_access_token", idcs_access_token)
        pulumi.set(__self__, "license_type", license_type)
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "network_endpoint_details", network_endpoint_details)
        pulumi.set(__self__, "private_access_channels", private_access_channels)
        pulumi.set(__self__, "service_url", service_url)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)
        pulumi.set(__self__, "vanity_url_details", vanity_url_details)

    @property
    @pulumi.getter
    def capacity(self) -> 'outputs.GetAnalyticsInstancesAnalyticsInstanceCapacityResult':
        """
        Service instance capacity metadata (e.g.: OLPU count, number of users, ...etc...).
        """
        return pulumi.get(self, "capacity")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description of the vanity url.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="emailNotification")
    def email_notification(self) -> str:
        """
        Email address receiving notifications.
        """
        return pulumi.get(self, "email_notification")

    @property
    @pulumi.getter(name="featureSet")
    def feature_set(self) -> str:
        """
        A filter to only return resources matching the feature set. Values are case-insensitive.
        """
        return pulumi.get(self, "feature_set")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idcsAccessToken")
    def idcs_access_token(self) -> str:
        return pulumi.get(self, "idcs_access_token")

    @property
    @pulumi.getter(name="licenseType")
    def license_type(self) -> str:
        """
        The license used for the service.
        """
        return pulumi.get(self, "license_type")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return only resources that match the given name exactly.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="networkEndpointDetails")
    def network_endpoint_details(self) -> 'outputs.GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsResult':
        """
        Base representation of a network endpoint.
        """
        return pulumi.get(self, "network_endpoint_details")

    @property
    @pulumi.getter(name="privateAccessChannels")
    def private_access_channels(self) -> Mapping[str, Any]:
        """
        Map of PrivateAccessChannel unique identifier key as KEY and PrivateAccessChannel Object as VALUE.
        """
        return pulumi.get(self, "private_access_channels")

    @property
    @pulumi.getter(name="serviceUrl")
    def service_url(self) -> str:
        """
        URL of the Analytics service.
        """
        return pulumi.get(self, "service_url")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        A filter to only return resources matching the lifecycle state. The state value is case-insensitive.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the instance was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The date and time the instance was last updated (in the format defined by RFC3339). This timestamp represents updates made through this API. External events do not influence it.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="vanityUrlDetails")
    def vanity_url_details(self) -> Mapping[str, Any]:
        """
        Map of VanityUrl unique identifier key as KEY and VanityUrl Object as VALUE.
        """
        return pulumi.get(self, "vanity_url_details")


@pulumi.output_type
class GetAnalyticsInstancesAnalyticsInstanceCapacityResult(dict):
    def __init__(__self__, *,
                 capacity_type: str,
                 capacity_value: int):
        """
        :param str capacity_type: A filter to only return resources matching the capacity type enum. Values are case-insensitive.
        :param int capacity_value: The capacity value selected (OLPU count, number of users, ...etc...). This parameter affects the number of CPUs, amount of memory or other resources allocated to the instance.
        """
        pulumi.set(__self__, "capacity_type", capacity_type)
        pulumi.set(__self__, "capacity_value", capacity_value)

    @property
    @pulumi.getter(name="capacityType")
    def capacity_type(self) -> str:
        """
        A filter to only return resources matching the capacity type enum. Values are case-insensitive.
        """
        return pulumi.get(self, "capacity_type")

    @property
    @pulumi.getter(name="capacityValue")
    def capacity_value(self) -> int:
        """
        The capacity value selected (OLPU count, number of users, ...etc...). This parameter affects the number of CPUs, amount of memory or other resources allocated to the instance.
        """
        return pulumi.get(self, "capacity_value")


@pulumi.output_type
class GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsResult(dict):
    def __init__(__self__, *,
                 network_endpoint_type: str,
                 subnet_id: str,
                 vcn_id: str,
                 whitelisted_ips: Sequence[str],
                 whitelisted_vcns: Sequence['outputs.GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnResult']):
        """
        :param str network_endpoint_type: The type of network endpoint.
        :param str subnet_id: OCID of the customer subnet connected to private access channel.
        :param str vcn_id: OCID of the customer VCN peered with private access channel.
        :param Sequence[str] whitelisted_ips: Source IP addresses or IP address ranges igress rules.
        :param Sequence['GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnArgs'] whitelisted_vcns: Virtual Cloud Networks allowed to access this network endpoint.
        """
        pulumi.set(__self__, "network_endpoint_type", network_endpoint_type)
        pulumi.set(__self__, "subnet_id", subnet_id)
        pulumi.set(__self__, "vcn_id", vcn_id)
        pulumi.set(__self__, "whitelisted_ips", whitelisted_ips)
        pulumi.set(__self__, "whitelisted_vcns", whitelisted_vcns)

    @property
    @pulumi.getter(name="networkEndpointType")
    def network_endpoint_type(self) -> str:
        """
        The type of network endpoint.
        """
        return pulumi.get(self, "network_endpoint_type")

    @property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> str:
        """
        OCID of the customer subnet connected to private access channel.
        """
        return pulumi.get(self, "subnet_id")

    @property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> str:
        """
        OCID of the customer VCN peered with private access channel.
        """
        return pulumi.get(self, "vcn_id")

    @property
    @pulumi.getter(name="whitelistedIps")
    def whitelisted_ips(self) -> Sequence[str]:
        """
        Source IP addresses or IP address ranges igress rules.
        """
        return pulumi.get(self, "whitelisted_ips")

    @property
    @pulumi.getter(name="whitelistedVcns")
    def whitelisted_vcns(self) -> Sequence['outputs.GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnResult']:
        """
        Virtual Cloud Networks allowed to access this network endpoint.
        """
        return pulumi.get(self, "whitelisted_vcns")


@pulumi.output_type
class GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnResult(dict):
    def __init__(__self__, *,
                 id: str,
                 whitelisted_ips: Sequence[str]):
        """
        :param str id: The Virtual Cloud Network OCID.
        :param Sequence[str] whitelisted_ips: Source IP addresses or IP address ranges igress rules.
        """
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "whitelisted_ips", whitelisted_ips)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="whitelistedIps")
    def whitelisted_ips(self) -> Sequence[str]:
        """
        Source IP addresses or IP address ranges igress rules.
        """
        return pulumi.get(self, "whitelisted_ips")


@pulumi.output_type
class GetAnalyticsInstancesFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to return only resources that match the given name exactly.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return only resources that match the given name exactly.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


