# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetViewResult',
    'AwaitableGetViewResult',
    'get_view',
]

@pulumi.output_type
class GetViewResult:
    """
    A collection of values returned by getView.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, is_protected=None, scope=None, self=None, state=None, time_created=None, time_updated=None, view_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_protected and not isinstance(is_protected, bool):
            raise TypeError("Expected argument 'is_protected' to be a bool")
        pulumi.set(__self__, "is_protected", is_protected)
        if scope and not isinstance(scope, str):
            raise TypeError("Expected argument 'scope' to be a str")
        pulumi.set(__self__, "scope", scope)
        if self and not isinstance(self, str):
            raise TypeError("Expected argument 'self' to be a str")
        pulumi.set(__self__, "self", self)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if view_id and not isinstance(view_id, str):
            raise TypeError("Expected argument 'view_id' to be a str")
        pulumi.set(__self__, "view_id", view_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the owning compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The display name of the view.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The OCID of the view.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isProtected")
    def is_protected(self) -> bool:
        """
        A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
        """
        return pulumi.get(self, "is_protected")

    @property
    @pulumi.getter
    def scope(self) -> str:
        return pulumi.get(self, "scope")

    @property
    @pulumi.getter
    def self(self) -> str:
        """
        The canonical absolute URL of the resource.
        """
        return pulumi.get(self, "self")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the resource.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="viewId")
    def view_id(self) -> str:
        return pulumi.get(self, "view_id")


class AwaitableGetViewResult(GetViewResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetViewResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_protected=self.is_protected,
            scope=self.scope,
            self=self.self,
            state=self.state,
            time_created=self.time_created,
            time_updated=self.time_updated,
            view_id=self.view_id)


def get_view(scope: Optional[str] = None,
             view_id: Optional[str] = None,
             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetViewResult:
    """
    This data source provides details about a specific View resource in Oracle Cloud Infrastructure DNS service.

    Gets information about a specific view. Note that attempting to get a
    view in the DELETED lifecycleState will result in a `404` response to be
    consistent with other operations of the API. Requires a `PRIVATE` scope query parameter.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_view = oci.dns.get_view(view_id=oci_dns_view["test_view"]["id"],
        scope="PRIVATE")
    ```


    :param str scope: Value must be `PRIVATE` when listing views for private zones.
    :param str view_id: The OCID of the target view.
    """
    __args__ = dict()
    __args__['scope'] = scope
    __args__['viewId'] = view_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:dns/getView:getView', __args__, opts=opts, typ=GetViewResult).value

    return AwaitableGetViewResult(
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        is_protected=__ret__.is_protected,
        scope=__ret__.scope,
        self=__ret__.self,
        state=__ret__.state,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated,
        view_id=__ret__.view_id)
