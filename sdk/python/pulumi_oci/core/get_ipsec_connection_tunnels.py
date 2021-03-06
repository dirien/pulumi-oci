# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetIpsecConnectionTunnelsResult',
    'AwaitableGetIpsecConnectionTunnelsResult',
    'get_ipsec_connection_tunnels',
]

@pulumi.output_type
class GetIpsecConnectionTunnelsResult:
    """
    A collection of values returned by getIpsecConnectionTunnels.
    """
    def __init__(__self__, filters=None, id=None, ip_sec_connection_tunnels=None, ipsec_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ip_sec_connection_tunnels and not isinstance(ip_sec_connection_tunnels, list):
            raise TypeError("Expected argument 'ip_sec_connection_tunnels' to be a list")
        pulumi.set(__self__, "ip_sec_connection_tunnels", ip_sec_connection_tunnels)
        if ipsec_id and not isinstance(ipsec_id, str):
            raise TypeError("Expected argument 'ipsec_id' to be a str")
        pulumi.set(__self__, "ipsec_id", ipsec_id)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetIpsecConnectionTunnelsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="ipSecConnectionTunnels")
    def ip_sec_connection_tunnels(self) -> Sequence['outputs.GetIpsecConnectionTunnelsIpSecConnectionTunnelResult']:
        """
        The list of ip_sec_connection_tunnels.
        """
        return pulumi.get(self, "ip_sec_connection_tunnels")

    @property
    @pulumi.getter(name="ipsecId")
    def ipsec_id(self) -> str:
        return pulumi.get(self, "ipsec_id")


class AwaitableGetIpsecConnectionTunnelsResult(GetIpsecConnectionTunnelsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIpsecConnectionTunnelsResult(
            filters=self.filters,
            id=self.id,
            ip_sec_connection_tunnels=self.ip_sec_connection_tunnels,
            ipsec_id=self.ipsec_id)


def get_ipsec_connection_tunnels(filters: Optional[Sequence[pulumi.InputType['GetIpsecConnectionTunnelsFilterArgs']]] = None,
                                 ipsec_id: Optional[str] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIpsecConnectionTunnelsResult:
    """
    This data source provides the list of Ip Sec Connection Tunnels in Oracle Cloud Infrastructure Core service.

    Lists the tunnel information for the specified IPSec connection.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ip_sec_connection_tunnels = oci.core.get_ipsec_connection_tunnels(ipsec_id=oci_core_ipsec["test_ipsec"]["id"])
    ```


    :param str ipsec_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the IPSec connection.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['ipsecId'] = ipsec_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getIpsecConnectionTunnels:getIpsecConnectionTunnels', __args__, opts=opts, typ=GetIpsecConnectionTunnelsResult).value

    return AwaitableGetIpsecConnectionTunnelsResult(
        filters=__ret__.filters,
        id=__ret__.id,
        ip_sec_connection_tunnels=__ret__.ip_sec_connection_tunnels,
        ipsec_id=__ret__.ipsec_id)
