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
    'GetViewsResult',
    'AwaitableGetViewsResult',
    'get_views',
]

@pulumi.output_type
class GetViewsResult:
    """
    A collection of values returned by getViews.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, scope=None, state=None, views=None):
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
        if scope and not isinstance(scope, str):
            raise TypeError("Expected argument 'scope' to be a str")
        pulumi.set(__self__, "scope", scope)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if views and not isinstance(views, list):
            raise TypeError("Expected argument 'views' to be a list")
        pulumi.set(__self__, "views", views)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the owning compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The display name of the view.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetViewsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        The OCID of the view.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def scope(self) -> str:
        return pulumi.get(self, "scope")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the resource.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter
    def views(self) -> Sequence['outputs.GetViewsViewResult']:
        """
        The list of views.
        """
        return pulumi.get(self, "views")


class AwaitableGetViewsResult(GetViewsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetViewsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            scope=self.scope,
            state=self.state,
            views=self.views)


def get_views(compartment_id: Optional[str] = None,
              display_name: Optional[str] = None,
              filters: Optional[Sequence[pulumi.InputType['GetViewsFilterArgs']]] = None,
              id: Optional[str] = None,
              scope: Optional[str] = None,
              state: Optional[str] = None,
              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetViewsResult:
    """
    This data source provides the list of Views in Oracle Cloud Infrastructure DNS service.

    Gets a list of all views within a compartment. The collection can
    be filtered by display name, id, or lifecycle state. It can be sorted
    on creation time or displayName both in ASC or DESC order. Note that
    when no lifecycleState query parameter is provided, the collection
    does not include views in the DELETED lifecycleState to be consistent
    with other operations of the API. Requires a `PRIVATE` scope query parameter.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_views = oci.dns.get_views(compartment_id=var["compartment_id"],
        scope="PRIVATE",
        display_name=var["view_display_name"],
        id=var["view_id"],
        state=var["view_state"])
    ```


    :param str compartment_id: The OCID of the compartment the resource belongs to.
    :param str display_name: The displayName of a resource.
    :param str id: The OCID of a resource.
    :param str scope: Value must be `PRIVATE` when listing private views.
    :param str state: The state of a resource.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['scope'] = scope
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:dns/getViews:getViews', __args__, opts=opts, typ=GetViewsResult).value

    return AwaitableGetViewsResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        scope=__ret__.scope,
        state=__ret__.state,
        views=__ret__.views)
