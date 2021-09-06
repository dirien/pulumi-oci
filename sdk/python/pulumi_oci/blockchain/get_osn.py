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
    'GetOsnResult',
    'AwaitableGetOsnResult',
    'get_osn',
]

@pulumi.output_type
class GetOsnResult:
    """
    A collection of values returned by getOsn.
    """
    def __init__(__self__, ad=None, blockchain_platform_id=None, id=None, ocpu_allocation_param=None, osn_id=None, osn_key=None, state=None):
        if ad and not isinstance(ad, str):
            raise TypeError("Expected argument 'ad' to be a str")
        pulumi.set(__self__, "ad", ad)
        if blockchain_platform_id and not isinstance(blockchain_platform_id, str):
            raise TypeError("Expected argument 'blockchain_platform_id' to be a str")
        pulumi.set(__self__, "blockchain_platform_id", blockchain_platform_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ocpu_allocation_param and not isinstance(ocpu_allocation_param, dict):
            raise TypeError("Expected argument 'ocpu_allocation_param' to be a dict")
        pulumi.set(__self__, "ocpu_allocation_param", ocpu_allocation_param)
        if osn_id and not isinstance(osn_id, str):
            raise TypeError("Expected argument 'osn_id' to be a str")
        pulumi.set(__self__, "osn_id", osn_id)
        if osn_key and not isinstance(osn_key, str):
            raise TypeError("Expected argument 'osn_key' to be a str")
        pulumi.set(__self__, "osn_key", osn_key)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter
    def ad(self) -> str:
        """
        Availability Domain of OSN
        """
        return pulumi.get(self, "ad")

    @property
    @pulumi.getter(name="blockchainPlatformId")
    def blockchain_platform_id(self) -> str:
        return pulumi.get(self, "blockchain_platform_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="ocpuAllocationParam")
    def ocpu_allocation_param(self) -> 'outputs.GetOsnOcpuAllocationParamResult':
        """
        OCPU allocation parameter
        """
        return pulumi.get(self, "ocpu_allocation_param")

    @property
    @pulumi.getter(name="osnId")
    def osn_id(self) -> str:
        return pulumi.get(self, "osn_id")

    @property
    @pulumi.getter(name="osnKey")
    def osn_key(self) -> str:
        """
        OSN identifier
        """
        return pulumi.get(self, "osn_key")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the OSN.
        """
        return pulumi.get(self, "state")


class AwaitableGetOsnResult(GetOsnResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOsnResult(
            ad=self.ad,
            blockchain_platform_id=self.blockchain_platform_id,
            id=self.id,
            ocpu_allocation_param=self.ocpu_allocation_param,
            osn_id=self.osn_id,
            osn_key=self.osn_key,
            state=self.state)


def get_osn(blockchain_platform_id: Optional[str] = None,
            osn_id: Optional[str] = None,
            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOsnResult:
    """
    This data source provides details about a specific Osn resource in Oracle Cloud Infrastructure Blockchain service.

    Gets information about an OSN identified by the specific id

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_osn = oci.blockchain.get_osn(blockchain_platform_id=oci_blockchain_blockchain_platform["test_blockchain_platform"]["id"],
        osn_id=oci_blockchain_osn["test_osn"]["id"])
    ```


    :param str blockchain_platform_id: Unique service identifier.
    :param str osn_id: OSN identifier.
    """
    __args__ = dict()
    __args__['blockchainPlatformId'] = blockchain_platform_id
    __args__['osnId'] = osn_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:blockchain/getOsn:getOsn', __args__, opts=opts, typ=GetOsnResult).value

    return AwaitableGetOsnResult(
        ad=__ret__.ad,
        blockchain_platform_id=__ret__.blockchain_platform_id,
        id=__ret__.id,
        ocpu_allocation_param=__ret__.ocpu_allocation_param,
        osn_id=__ret__.osn_id,
        osn_key=__ret__.osn_key,
        state=__ret__.state)
