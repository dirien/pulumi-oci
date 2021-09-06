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
    'GetPrivateApplicationsResult',
    'AwaitableGetPrivateApplicationsResult',
    'get_private_applications',
]

@pulumi.output_type
class GetPrivateApplicationsResult:
    """
    A collection of values returned by getPrivateApplications.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, private_application_collections=None, private_application_id=None):
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
        if private_application_collections and not isinstance(private_application_collections, list):
            raise TypeError("Expected argument 'private_application_collections' to be a list")
        pulumi.set(__self__, "private_application_collections", private_application_collections)
        if private_application_id and not isinstance(private_application_id, str):
            raise TypeError("Expected argument 'private_application_id' to be a str")
        pulumi.set(__self__, "private_application_id", private_application_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the private application resides.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The name used to refer to the uploaded data.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetPrivateApplicationsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="privateApplicationCollections")
    def private_application_collections(self) -> Sequence['outputs.GetPrivateApplicationsPrivateApplicationCollectionResult']:
        """
        The list of private_application_collection.
        """
        return pulumi.get(self, "private_application_collections")

    @property
    @pulumi.getter(name="privateApplicationId")
    def private_application_id(self) -> Optional[str]:
        return pulumi.get(self, "private_application_id")


class AwaitableGetPrivateApplicationsResult(GetPrivateApplicationsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPrivateApplicationsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            private_application_collections=self.private_application_collections,
            private_application_id=self.private_application_id)


def get_private_applications(compartment_id: Optional[str] = None,
                             display_name: Optional[str] = None,
                             filters: Optional[Sequence[pulumi.InputType['GetPrivateApplicationsFilterArgs']]] = None,
                             private_application_id: Optional[str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetPrivateApplicationsResult:
    """
    This data source provides the list of Private Applications in Oracle Cloud Infrastructure Service Catalog service.

    Lists all the private applications in a given compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_private_applications = oci.servicecatalog.get_private_applications(compartment_id=var["compartment_id"],
        display_name=var["private_application_display_name"],
        private_application_id=oci_service_catalog_private_application["test_private_application"]["id"])
    ```


    :param str compartment_id: The unique identifier for the compartment.
    :param str display_name: Exact match name filter.
    :param str private_application_id: The unique identifier for the private application.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['privateApplicationId'] = private_application_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:servicecatalog/getPrivateApplications:getPrivateApplications', __args__, opts=opts, typ=GetPrivateApplicationsResult).value

    return AwaitableGetPrivateApplicationsResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        private_application_collections=__ret__.private_application_collections,
        private_application_id=__ret__.private_application_id)
