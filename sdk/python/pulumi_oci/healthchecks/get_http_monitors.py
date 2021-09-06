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
    'GetHttpMonitorsResult',
    'AwaitableGetHttpMonitorsResult',
    'get_http_monitors',
]

@pulumi.output_type
class GetHttpMonitorsResult:
    """
    A collection of values returned by getHttpMonitors.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, home_region=None, http_monitors=None, id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if home_region and not isinstance(home_region, str):
            raise TypeError("Expected argument 'home_region' to be a str")
        pulumi.set(__self__, "home_region", home_region)
        if http_monitors and not isinstance(http_monitors, list):
            raise TypeError("Expected argument 'http_monitors' to be a list")
        pulumi.set(__self__, "http_monitors", http_monitors)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly and mutable name suitable for display in a user interface.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetHttpMonitorsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter(name="homeRegion")
    def home_region(self) -> Optional[str]:
        """
        The region where updates must be made and where results must be fetched from.
        """
        return pulumi.get(self, "home_region")

    @property
    @pulumi.getter(name="httpMonitors")
    def http_monitors(self) -> Sequence['outputs.GetHttpMonitorsHttpMonitorResult']:
        """
        The list of http_monitors.
        """
        return pulumi.get(self, "http_monitors")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetHttpMonitorsResult(GetHttpMonitorsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetHttpMonitorsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            home_region=self.home_region,
            http_monitors=self.http_monitors,
            id=self.id)


def get_http_monitors(compartment_id: Optional[str] = None,
                      display_name: Optional[str] = None,
                      filters: Optional[Sequence[pulumi.InputType['GetHttpMonitorsFilterArgs']]] = None,
                      home_region: Optional[str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetHttpMonitorsResult:
    """
    This data source provides the list of Http Monitors in Oracle Cloud Infrastructure Health Checks service.

    Gets a list of HTTP monitors.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_http_monitors = oci.healthchecks.get_http_monitors(compartment_id=var["compartment_id"],
        display_name=var["http_monitor_display_name"],
        home_region=var["http_monitor_home_region"])
    ```


    :param str compartment_id: Filters results by compartment.
    :param str display_name: Filters results that exactly match the `displayName` field.
    :param str home_region: Filters results that match the `homeRegion`.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['homeRegion'] = home_region
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:healthchecks/getHttpMonitors:getHttpMonitors', __args__, opts=opts, typ=GetHttpMonitorsResult).value

    return AwaitableGetHttpMonitorsResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        home_region=__ret__.home_region,
        http_monitors=__ret__.http_monitors,
        id=__ret__.id)
