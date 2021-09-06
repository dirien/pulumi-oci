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
    'GetPrivateApplicationResult',
    'AwaitableGetPrivateApplicationResult',
    'get_private_application',
]

@pulumi.output_type
class GetPrivateApplicationResult:
    """
    A collection of values returned by getPrivateApplication.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, logo=None, logo_file_base64encoded=None, long_description=None, package_details=None, package_type=None, private_application_id=None, short_description=None, state=None, time_created=None, time_updated=None):
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
        if logo and not isinstance(logo, dict):
            raise TypeError("Expected argument 'logo' to be a dict")
        pulumi.set(__self__, "logo", logo)
        if logo_file_base64encoded and not isinstance(logo_file_base64encoded, str):
            raise TypeError("Expected argument 'logo_file_base64encoded' to be a str")
        pulumi.set(__self__, "logo_file_base64encoded", logo_file_base64encoded)
        if long_description and not isinstance(long_description, str):
            raise TypeError("Expected argument 'long_description' to be a str")
        pulumi.set(__self__, "long_description", long_description)
        if package_details and not isinstance(package_details, dict):
            raise TypeError("Expected argument 'package_details' to be a dict")
        pulumi.set(__self__, "package_details", package_details)
        if package_type and not isinstance(package_type, str):
            raise TypeError("Expected argument 'package_type' to be a str")
        pulumi.set(__self__, "package_type", package_type)
        if private_application_id and not isinstance(private_application_id, str):
            raise TypeError("Expected argument 'private_application_id' to be a str")
        pulumi.set(__self__, "private_application_id", private_application_id)
        if short_description and not isinstance(short_description, str):
            raise TypeError("Expected argument 'short_description' to be a str")
        pulumi.set(__self__, "short_description", short_description)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the private application resides.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The name used to refer to the uploaded data.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The unique identifier for the private application in Marketplace.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def logo(self) -> 'outputs.GetPrivateApplicationLogoResult':
        """
        The model for uploaded binary data, like logos and images.
        """
        return pulumi.get(self, "logo")

    @property
    @pulumi.getter(name="logoFileBase64encoded")
    def logo_file_base64encoded(self) -> str:
        return pulumi.get(self, "logo_file_base64encoded")

    @property
    @pulumi.getter(name="longDescription")
    def long_description(self) -> str:
        """
        A long description of the private application.
        """
        return pulumi.get(self, "long_description")

    @property
    @pulumi.getter(name="packageDetails")
    def package_details(self) -> 'outputs.GetPrivateApplicationPackageDetailsResult':
        return pulumi.get(self, "package_details")

    @property
    @pulumi.getter(name="packageType")
    def package_type(self) -> str:
        """
        Type of packages within this private application.
        """
        return pulumi.get(self, "package_type")

    @property
    @pulumi.getter(name="privateApplicationId")
    def private_application_id(self) -> str:
        return pulumi.get(self, "private_application_id")

    @property
    @pulumi.getter(name="shortDescription")
    def short_description(self) -> str:
        """
        A short description of the private application.
        """
        return pulumi.get(self, "short_description")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The lifecycle state of the private application.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetPrivateApplicationResult(GetPrivateApplicationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPrivateApplicationResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            logo=self.logo,
            logo_file_base64encoded=self.logo_file_base64encoded,
            long_description=self.long_description,
            package_details=self.package_details,
            package_type=self.package_type,
            private_application_id=self.private_application_id,
            short_description=self.short_description,
            state=self.state,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_private_application(private_application_id: Optional[str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetPrivateApplicationResult:
    """
    This data source provides details about a specific Private Application resource in Oracle Cloud Infrastructure Service Catalog service.

    Gets the details of the specified private application.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_private_application = oci.servicecatalog.get_private_application(private_application_id=oci_service_catalog_private_application["test_private_application"]["id"])
    ```


    :param str private_application_id: The unique identifier for the private application.
    """
    __args__ = dict()
    __args__['privateApplicationId'] = private_application_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:servicecatalog/getPrivateApplication:getPrivateApplication', __args__, opts=opts, typ=GetPrivateApplicationResult).value

    return AwaitableGetPrivateApplicationResult(
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        logo=__ret__.logo,
        logo_file_base64encoded=__ret__.logo_file_base64encoded,
        long_description=__ret__.long_description,
        package_details=__ret__.package_details,
        package_type=__ret__.package_type,
        private_application_id=__ret__.private_application_id,
        short_description=__ret__.short_description,
        state=__ret__.state,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)
