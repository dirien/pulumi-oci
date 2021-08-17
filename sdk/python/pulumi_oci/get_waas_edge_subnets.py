# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetWaasEdgeSubnetsResult',
    'AwaitableGetWaasEdgeSubnetsResult',
    'get_waas_edge_subnets',
]

@pulumi.output_type
class GetWaasEdgeSubnetsResult:
    """
    A collection of values returned by GetWaasEdgeSubnets.
    """
    def __init__(__self__, edge_subnets=None, filters=None, id=None):
        if edge_subnets and not isinstance(edge_subnets, list):
            raise TypeError("Expected argument 'edge_subnets' to be a list")
        pulumi.set(__self__, "edge_subnets", edge_subnets)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="edgeSubnets")
    def edge_subnets(self) -> Sequence['outputs.GetWaasEdgeSubnetsEdgeSubnetResult']:
        """
        The list of edge_subnets.
        """
        return pulumi.get(self, "edge_subnets")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetWaasEdgeSubnetsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetWaasEdgeSubnetsResult(GetWaasEdgeSubnetsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetWaasEdgeSubnetsResult(
            edge_subnets=self.edge_subnets,
            filters=self.filters,
            id=self.id)


def get_waas_edge_subnets(filters: Optional[Sequence[pulumi.InputType['GetWaasEdgeSubnetsFilterArgs']]] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetWaasEdgeSubnetsResult:
    """
    This data source provides the list of Edge Subnets in Oracle Cloud Infrastructure Web Application Acceleration and Security service.

    Return the list of the tenant's edge node subnets. Use these CIDR blocks to restrict incoming traffic to your origin. These subnets are owned by Oracle Cloud Infrastructure and forward traffic to customer origins. They are not associated with specific regions or compartments.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_edge_subnets = oci.get_waas_edge_subnets()
    ```
    """
    __args__ = dict()
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:index/getWaasEdgeSubnets:GetWaasEdgeSubnets', __args__, opts=opts, typ=GetWaasEdgeSubnetsResult).value

    return AwaitableGetWaasEdgeSubnetsResult(
        edge_subnets=__ret__.edge_subnets,
        filters=__ret__.filters,
        id=__ret__.id)