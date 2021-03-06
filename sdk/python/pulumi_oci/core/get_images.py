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
    'GetImagesResult',
    'AwaitableGetImagesResult',
    'get_images',
]

@pulumi.output_type
class GetImagesResult:
    """
    A collection of values returned by getImages.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, images=None, operating_system=None, operating_system_version=None, shape=None, sort_by=None, sort_order=None, state=None):
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
        if images and not isinstance(images, list):
            raise TypeError("Expected argument 'images' to be a list")
        pulumi.set(__self__, "images", images)
        if operating_system and not isinstance(operating_system, str):
            raise TypeError("Expected argument 'operating_system' to be a str")
        pulumi.set(__self__, "operating_system", operating_system)
        if operating_system_version and not isinstance(operating_system_version, str):
            raise TypeError("Expected argument 'operating_system_version' to be a str")
        pulumi.set(__self__, "operating_system_version", operating_system_version)
        if shape and not isinstance(shape, str):
            raise TypeError("Expected argument 'shape' to be a str")
        pulumi.set(__self__, "shape", shape)
        if sort_by and not isinstance(sort_by, str):
            raise TypeError("Expected argument 'sort_by' to be a str")
        pulumi.set(__self__, "sort_by", sort_by)
        if sort_order and not isinstance(sort_order, str):
            raise TypeError("Expected argument 'sort_order' to be a str")
        pulumi.set(__self__, "sort_order", sort_order)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment containing the instance you want to use as the basis for the image.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetImagesFilterResult']]:
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
    def images(self) -> Sequence['outputs.GetImagesImageResult']:
        """
        The list of images.
        """
        return pulumi.get(self, "images")

    @property
    @pulumi.getter(name="operatingSystem")
    def operating_system(self) -> Optional[str]:
        """
        The image's operating system.  Example: `Oracle Linux`
        """
        return pulumi.get(self, "operating_system")

    @property
    @pulumi.getter(name="operatingSystemVersion")
    def operating_system_version(self) -> Optional[str]:
        """
        The image's operating system version.  Example: `7.2`
        """
        return pulumi.get(self, "operating_system_version")

    @property
    @pulumi.getter
    def shape(self) -> Optional[str]:
        return pulumi.get(self, "shape")

    @property
    @pulumi.getter(name="sortBy")
    def sort_by(self) -> Optional[str]:
        return pulumi.get(self, "sort_by")

    @property
    @pulumi.getter(name="sortOrder")
    def sort_order(self) -> Optional[str]:
        return pulumi.get(self, "sort_order")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the image.
        """
        return pulumi.get(self, "state")


class AwaitableGetImagesResult(GetImagesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetImagesResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            images=self.images,
            operating_system=self.operating_system,
            operating_system_version=self.operating_system_version,
            shape=self.shape,
            sort_by=self.sort_by,
            sort_order=self.sort_order,
            state=self.state)


def get_images(compartment_id: Optional[str] = None,
               display_name: Optional[str] = None,
               filters: Optional[Sequence[pulumi.InputType['GetImagesFilterArgs']]] = None,
               operating_system: Optional[str] = None,
               operating_system_version: Optional[str] = None,
               shape: Optional[str] = None,
               sort_by: Optional[str] = None,
               sort_order: Optional[str] = None,
               state: Optional[str] = None,
               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetImagesResult:
    """
    This data source provides the list of Images in Oracle Cloud Infrastructure Core service.

    Lists the available images in the specified compartment, including
    [platform images](https://docs.cloud.oracle.com/iaas/Content/Compute/References/images.htm) and
    [custom images](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingcustomimages.htm) that have
    been created.

    The list of images that's returned is ordered to first show all
    platform images, then all custom images. The order of images might
    change when new images are released.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_images = oci.core.get_images(compartment_id=var["compartment_id"],
        display_name=var["image_display_name"],
        operating_system=var["image_operating_system"],
        operating_system_version=var["image_operating_system_version"],
        shape=var["image_shape"],
        state=var["image_state"],
        sort_by=var["image_sort_by"],
        sort_order=var["image_sort_order"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    :param str operating_system: The image's operating system.  Example: `Oracle Linux`
    :param str operating_system_version: The image's operating system version.  Example: `7.2`
    :param str shape: Shape name.
    :param str sort_by: Sort the resources returned, by creation time or display name. Example `TIMECREATED` or `DISPLAYNAME`.
    :param str sort_order: The sort order to use, either ascending (`ASC`) or descending (`DESC`).
    :param str state: A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['operatingSystem'] = operating_system
    __args__['operatingSystemVersion'] = operating_system_version
    __args__['shape'] = shape
    __args__['sortBy'] = sort_by
    __args__['sortOrder'] = sort_order
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getImages:getImages', __args__, opts=opts, typ=GetImagesResult).value

    return AwaitableGetImagesResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        images=__ret__.images,
        operating_system=__ret__.operating_system,
        operating_system_version=__ret__.operating_system_version,
        shape=__ret__.shape,
        sort_by=__ret__.sort_by,
        sort_order=__ret__.sort_order,
        state=__ret__.state)
