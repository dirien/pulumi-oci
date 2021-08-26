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

__all__ = ['PrivateApplicationArgs', 'PrivateApplication']

@pulumi.input_type
class PrivateApplicationArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 display_name: pulumi.Input[str],
                 package_details: pulumi.Input['PrivateApplicationPackageDetailsArgs'],
                 short_description: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 logo_file_base64encoded: Optional[pulumi.Input[str]] = None,
                 long_description: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a PrivateApplication resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
        :param pulumi.Input[str] display_name: (Updatable) The name of the private application.
        :param pulumi.Input['PrivateApplicationPackageDetailsArgs'] package_details: A base object for creating a private application package.
        :param pulumi.Input[str] short_description: (Updatable) A short description of the private application.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] logo_file_base64encoded: (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
        :param pulumi.Input[str] long_description: (Updatable) A long description of the private application.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "package_details", package_details)
        pulumi.set(__self__, "short_description", short_description)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if logo_file_base64encoded is not None:
            pulumi.set(__self__, "logo_file_base64encoded", logo_file_base64encoded)
        if long_description is not None:
            pulumi.set(__self__, "long_description", long_description)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[str]:
        """
        (Updatable) The name of the private application.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="packageDetails")
    def package_details(self) -> pulumi.Input['PrivateApplicationPackageDetailsArgs']:
        """
        A base object for creating a private application package.
        """
        return pulumi.get(self, "package_details")

    @package_details.setter
    def package_details(self, value: pulumi.Input['PrivateApplicationPackageDetailsArgs']):
        pulumi.set(self, "package_details", value)

    @property
    @pulumi.getter(name="shortDescription")
    def short_description(self) -> pulumi.Input[str]:
        """
        (Updatable) A short description of the private application.
        """
        return pulumi.get(self, "short_description")

    @short_description.setter
    def short_description(self, value: pulumi.Input[str]):
        pulumi.set(self, "short_description", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="logoFileBase64encoded")
    def logo_file_base64encoded(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
        """
        return pulumi.get(self, "logo_file_base64encoded")

    @logo_file_base64encoded.setter
    def logo_file_base64encoded(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "logo_file_base64encoded", value)

    @property
    @pulumi.getter(name="longDescription")
    def long_description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A long description of the private application.
        """
        return pulumi.get(self, "long_description")

    @long_description.setter
    def long_description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "long_description", value)


@pulumi.input_type
class _PrivateApplicationState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 logo: Optional[pulumi.Input['PrivateApplicationLogoArgs']] = None,
                 logo_file_base64encoded: Optional[pulumi.Input[str]] = None,
                 long_description: Optional[pulumi.Input[str]] = None,
                 package_details: Optional[pulumi.Input['PrivateApplicationPackageDetailsArgs']] = None,
                 package_type: Optional[pulumi.Input[str]] = None,
                 short_description: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering PrivateApplication resources.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the private application.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input['PrivateApplicationLogoArgs'] logo: The model for uploaded binary data, like logos and images.
        :param pulumi.Input[str] logo_file_base64encoded: (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
        :param pulumi.Input[str] long_description: (Updatable) A long description of the private application.
        :param pulumi.Input['PrivateApplicationPackageDetailsArgs'] package_details: A base object for creating a private application package.
        :param pulumi.Input[str] package_type: The package's type.
        :param pulumi.Input[str] short_description: (Updatable) A short description of the private application.
        :param pulumi.Input[str] state: The lifecycle state of the private application.
        :param pulumi.Input[str] time_created: The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
        :param pulumi.Input[str] time_updated: The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if logo is not None:
            pulumi.set(__self__, "logo", logo)
        if logo_file_base64encoded is not None:
            pulumi.set(__self__, "logo_file_base64encoded", logo_file_base64encoded)
        if long_description is not None:
            pulumi.set(__self__, "long_description", long_description)
        if package_details is not None:
            pulumi.set(__self__, "package_details", package_details)
        if package_type is not None:
            pulumi.set(__self__, "package_type", package_type)
        if short_description is not None:
            pulumi.set(__self__, "short_description", short_description)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The name of the private application.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter
    def logo(self) -> Optional[pulumi.Input['PrivateApplicationLogoArgs']]:
        """
        The model for uploaded binary data, like logos and images.
        """
        return pulumi.get(self, "logo")

    @logo.setter
    def logo(self, value: Optional[pulumi.Input['PrivateApplicationLogoArgs']]):
        pulumi.set(self, "logo", value)

    @property
    @pulumi.getter(name="logoFileBase64encoded")
    def logo_file_base64encoded(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
        """
        return pulumi.get(self, "logo_file_base64encoded")

    @logo_file_base64encoded.setter
    def logo_file_base64encoded(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "logo_file_base64encoded", value)

    @property
    @pulumi.getter(name="longDescription")
    def long_description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A long description of the private application.
        """
        return pulumi.get(self, "long_description")

    @long_description.setter
    def long_description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "long_description", value)

    @property
    @pulumi.getter(name="packageDetails")
    def package_details(self) -> Optional[pulumi.Input['PrivateApplicationPackageDetailsArgs']]:
        """
        A base object for creating a private application package.
        """
        return pulumi.get(self, "package_details")

    @package_details.setter
    def package_details(self, value: Optional[pulumi.Input['PrivateApplicationPackageDetailsArgs']]):
        pulumi.set(self, "package_details", value)

    @property
    @pulumi.getter(name="packageType")
    def package_type(self) -> Optional[pulumi.Input[str]]:
        """
        The package's type.
        """
        return pulumi.get(self, "package_type")

    @package_type.setter
    def package_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "package_type", value)

    @property
    @pulumi.getter(name="shortDescription")
    def short_description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A short description of the private application.
        """
        return pulumi.get(self, "short_description")

    @short_description.setter
    def short_description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "short_description", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The lifecycle state of the private application.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class PrivateApplication(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 logo_file_base64encoded: Optional[pulumi.Input[str]] = None,
                 long_description: Optional[pulumi.Input[str]] = None,
                 package_details: Optional[pulumi.Input[pulumi.InputType['PrivateApplicationPackageDetailsArgs']]] = None,
                 short_description: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Private Application resource in Oracle Cloud Infrastructure Service Catalog service.

        Creates a private application along with a single package to be hosted.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_private_application = oci.servicecatalog.PrivateApplication("testPrivateApplication",
            compartment_id=var["compartment_id"],
            display_name=var["private_application_display_name"],
            package_details=oci.servicecatalog.PrivateApplicationPackageDetailsArgs(
                package_type=var["private_application_package_details_package_type"],
                version=var["private_application_package_details_version"],
                zip_file_base64encoded=var["private_application_package_details_zip_file_base64encoded"],
            ),
            short_description=var["private_application_short_description"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            freeform_tags={
                "bar-key": "value",
            },
            logo_file_base64encoded=var["private_application_logo_file_base64encoded"],
            long_description=var["private_application_long_description"])
        ```

        ## Import

        PrivateApplications can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:servicecatalog/privateApplication:PrivateApplication test_private_application "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the private application.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] logo_file_base64encoded: (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
        :param pulumi.Input[str] long_description: (Updatable) A long description of the private application.
        :param pulumi.Input[pulumi.InputType['PrivateApplicationPackageDetailsArgs']] package_details: A base object for creating a private application package.
        :param pulumi.Input[str] short_description: (Updatable) A short description of the private application.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: PrivateApplicationArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Private Application resource in Oracle Cloud Infrastructure Service Catalog service.

        Creates a private application along with a single package to be hosted.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_private_application = oci.servicecatalog.PrivateApplication("testPrivateApplication",
            compartment_id=var["compartment_id"],
            display_name=var["private_application_display_name"],
            package_details=oci.servicecatalog.PrivateApplicationPackageDetailsArgs(
                package_type=var["private_application_package_details_package_type"],
                version=var["private_application_package_details_version"],
                zip_file_base64encoded=var["private_application_package_details_zip_file_base64encoded"],
            ),
            short_description=var["private_application_short_description"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            freeform_tags={
                "bar-key": "value",
            },
            logo_file_base64encoded=var["private_application_logo_file_base64encoded"],
            long_description=var["private_application_long_description"])
        ```

        ## Import

        PrivateApplications can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:servicecatalog/privateApplication:PrivateApplication test_private_application "id"
        ```

        :param str resource_name: The name of the resource.
        :param PrivateApplicationArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(PrivateApplicationArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 logo_file_base64encoded: Optional[pulumi.Input[str]] = None,
                 long_description: Optional[pulumi.Input[str]] = None,
                 package_details: Optional[pulumi.Input[pulumi.InputType['PrivateApplicationPackageDetailsArgs']]] = None,
                 short_description: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = _utilities.get_version()
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = PrivateApplicationArgs.__new__(PrivateApplicationArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["logo_file_base64encoded"] = logo_file_base64encoded
            __props__.__dict__["long_description"] = long_description
            if package_details is None and not opts.urn:
                raise TypeError("Missing required property 'package_details'")
            __props__.__dict__["package_details"] = package_details
            if short_description is None and not opts.urn:
                raise TypeError("Missing required property 'short_description'")
            __props__.__dict__["short_description"] = short_description
            __props__.__dict__["logo"] = None
            __props__.__dict__["package_type"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(PrivateApplication, __self__).__init__(
            'oci:servicecatalog/privateApplication:PrivateApplication',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            logo: Optional[pulumi.Input[pulumi.InputType['PrivateApplicationLogoArgs']]] = None,
            logo_file_base64encoded: Optional[pulumi.Input[str]] = None,
            long_description: Optional[pulumi.Input[str]] = None,
            package_details: Optional[pulumi.Input[pulumi.InputType['PrivateApplicationPackageDetailsArgs']]] = None,
            package_type: Optional[pulumi.Input[str]] = None,
            short_description: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'PrivateApplication':
        """
        Get an existing PrivateApplication resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the private application.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[pulumi.InputType['PrivateApplicationLogoArgs']] logo: The model for uploaded binary data, like logos and images.
        :param pulumi.Input[str] logo_file_base64encoded: (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
        :param pulumi.Input[str] long_description: (Updatable) A long description of the private application.
        :param pulumi.Input[pulumi.InputType['PrivateApplicationPackageDetailsArgs']] package_details: A base object for creating a private application package.
        :param pulumi.Input[str] package_type: The package's type.
        :param pulumi.Input[str] short_description: (Updatable) A short description of the private application.
        :param pulumi.Input[str] state: The lifecycle state of the private application.
        :param pulumi.Input[str] time_created: The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
        :param pulumi.Input[str] time_updated: The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _PrivateApplicationState.__new__(_PrivateApplicationState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["logo"] = logo
        __props__.__dict__["logo_file_base64encoded"] = logo_file_base64encoded
        __props__.__dict__["long_description"] = long_description
        __props__.__dict__["package_details"] = package_details
        __props__.__dict__["package_type"] = package_type
        __props__.__dict__["short_description"] = short_description
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return PrivateApplication(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        (Updatable) The name of the private application.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def logo(self) -> pulumi.Output['outputs.PrivateApplicationLogo']:
        """
        The model for uploaded binary data, like logos and images.
        """
        return pulumi.get(self, "logo")

    @property
    @pulumi.getter(name="logoFileBase64encoded")
    def logo_file_base64encoded(self) -> pulumi.Output[str]:
        """
        (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
        """
        return pulumi.get(self, "logo_file_base64encoded")

    @property
    @pulumi.getter(name="longDescription")
    def long_description(self) -> pulumi.Output[str]:
        """
        (Updatable) A long description of the private application.
        """
        return pulumi.get(self, "long_description")

    @property
    @pulumi.getter(name="packageDetails")
    def package_details(self) -> pulumi.Output['outputs.PrivateApplicationPackageDetails']:
        """
        A base object for creating a private application package.
        """
        return pulumi.get(self, "package_details")

    @property
    @pulumi.getter(name="packageType")
    def package_type(self) -> pulumi.Output[str]:
        """
        The package's type.
        """
        return pulumi.get(self, "package_type")

    @property
    @pulumi.getter(name="shortDescription")
    def short_description(self) -> pulumi.Output[str]:
        """
        (Updatable) A short description of the private application.
        """
        return pulumi.get(self, "short_description")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The lifecycle state of the private application.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
        """
        return pulumi.get(self, "time_updated")

