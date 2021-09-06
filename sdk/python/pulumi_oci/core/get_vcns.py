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
    'GetVcnsResult',
    'AwaitableGetVcnsResult',
    'get_vcns',
]

@pulumi.output_type
class GetVcnsResult:
    """
    A collection of values returned by getVcns.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, state=None, virtual_networks=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if virtual_networks and not isinstance(virtual_networks, list):
            raise TypeError("Expected argument 'virtual_networks' to be a list")
        pulumi.set(__self__, "virtual_networks", virtual_networks)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment containing the VCN.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetVcnsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The VCN's current state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="virtualNetworks")
    def virtual_networks(self) -> Sequence['outputs.GetVcnsVirtualNetworkResult']:
        """
        The list of virtual_networks.
        """
        return pulumi.get(self, "virtual_networks")


class AwaitableGetVcnsResult(GetVcnsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetVcnsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            state=self.state,
            virtual_networks=self.virtual_networks)


def get_vcns(compartment_id: Optional[str] = None,
             display_name: Optional[str] = None,
             filters: Optional[Sequence[pulumi.InputType['GetVcnsFilterArgs']]] = None,
             state: Optional[str] = None,
             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetVcnsResult:
    """
    This data source provides the list of Vcns in Oracle Cloud Infrastructure Core service.

    Lists the virtual cloud networks (VCNs) in the specified compartment.

    ## Supported Aliases

    * `oci_core_virtual_networks`

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vcns = oci.core.get_vcns(compartment_id=var["compartment_id"],
        display_name=var["vcn_display_name"],
        state=var["vcn_state"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    :param str state: A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getVcns:getVcns', __args__, opts=opts, typ=GetVcnsResult).value

    return AwaitableGetVcnsResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        state=__ret__.state,
        virtual_networks=__ret__.virtual_networks)
