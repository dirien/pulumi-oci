# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetFastConnectProviderServiceKeyResult',
    'AwaitableGetFastConnectProviderServiceKeyResult',
    'get_fast_connect_provider_service_key',
]

@pulumi.output_type
class GetFastConnectProviderServiceKeyResult:
    """
    A collection of values returned by getFastConnectProviderServiceKey.
    """
    def __init__(__self__, bandwidth_shape_name=None, id=None, name=None, peering_location=None, provider_service_id=None, provider_service_key_name=None):
        if bandwidth_shape_name and not isinstance(bandwidth_shape_name, str):
            raise TypeError("Expected argument 'bandwidth_shape_name' to be a str")
        pulumi.set(__self__, "bandwidth_shape_name", bandwidth_shape_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if peering_location and not isinstance(peering_location, str):
            raise TypeError("Expected argument 'peering_location' to be a str")
        pulumi.set(__self__, "peering_location", peering_location)
        if provider_service_id and not isinstance(provider_service_id, str):
            raise TypeError("Expected argument 'provider_service_id' to be a str")
        pulumi.set(__self__, "provider_service_id", provider_service_id)
        if provider_service_key_name and not isinstance(provider_service_key_name, str):
            raise TypeError("Expected argument 'provider_service_key_name' to be a str")
        pulumi.set(__self__, "provider_service_key_name", provider_service_key_name)

    @property
    @pulumi.getter(name="bandwidthShapeName")
    def bandwidth_shape_name(self) -> str:
        """
        The provisioned data rate of the connection. To get a list of the available bandwidth levels (that is, shapes), see [ListFastConnectProviderServiceVirtualCircuitBandwidthShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/ListFastConnectProviderVirtualCircuitBandwidthShapes).  Example: `10 Gbps`
        """
        return pulumi.get(self, "bandwidth_shape_name")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The service key that the provider gives you when you set up a virtual circuit connection from the provider to Oracle Cloud Infrastructure. Use this value as the `providerServiceKeyName` query parameter for [GetFastConnectProviderServiceKey](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderServiceKey/GetFastConnectProviderServiceKey).
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="peeringLocation")
    def peering_location(self) -> str:
        """
        The provider's peering location.
        """
        return pulumi.get(self, "peering_location")

    @property
    @pulumi.getter(name="providerServiceId")
    def provider_service_id(self) -> str:
        return pulumi.get(self, "provider_service_id")

    @property
    @pulumi.getter(name="providerServiceKeyName")
    def provider_service_key_name(self) -> str:
        return pulumi.get(self, "provider_service_key_name")


class AwaitableGetFastConnectProviderServiceKeyResult(GetFastConnectProviderServiceKeyResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFastConnectProviderServiceKeyResult(
            bandwidth_shape_name=self.bandwidth_shape_name,
            id=self.id,
            name=self.name,
            peering_location=self.peering_location,
            provider_service_id=self.provider_service_id,
            provider_service_key_name=self.provider_service_key_name)


def get_fast_connect_provider_service_key(provider_service_id: Optional[str] = None,
                                          provider_service_key_name: Optional[str] = None,
                                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFastConnectProviderServiceKeyResult:
    """
    This data source provides details about a specific Fast Connect Provider Service Key resource in Oracle Cloud Infrastructure Core service.

    Gets the specified provider service key's information. Use this operation to validate a
    provider service key. An invalid key returns a 404 error.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fast_connect_provider_service_key = oci.core.get_fast_connect_provider_service_key(provider_service_id=data["oci_core_fast_connect_provider_services"]["test_fast_connect_provider_services"]["fast_connect_provider_services"][0]["id"],
        provider_service_key_name=var["fast_connect_provider_service_key_provider_service_key_name"])
    ```


    :param str provider_service_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the provider service.
    :param str provider_service_key_name: The provider service key that the provider gives you when you set up a virtual circuit connection from the provider to Oracle Cloud Infrastructure. You can set up that connection and get your provider service key at the provider's website or portal. For the portal location, see the `description` attribute of the [FastConnectProviderService](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/).
    """
    __args__ = dict()
    __args__['providerServiceId'] = provider_service_id
    __args__['providerServiceKeyName'] = provider_service_key_name
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getFastConnectProviderServiceKey:getFastConnectProviderServiceKey', __args__, opts=opts, typ=GetFastConnectProviderServiceKeyResult).value

    return AwaitableGetFastConnectProviderServiceKeyResult(
        bandwidth_shape_name=__ret__.bandwidth_shape_name,
        id=__ret__.id,
        name=__ret__.name,
        peering_location=__ret__.peering_location,
        provider_service_id=__ret__.provider_service_id,
        provider_service_key_name=__ret__.provider_service_key_name)
