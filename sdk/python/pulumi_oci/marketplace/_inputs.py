# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'PublicationIconArgs',
    'PublicationPackageDetailsArgs',
    'PublicationPackageDetailsEulaArgs',
    'PublicationPackageDetailsOperatingSystemArgs',
    'PublicationSupportContactArgs',
    'PublicationSupportedOperatingSystemArgs',
    'GetAcceptedAgreementsFilterArgs',
    'GetCategoriesFilterArgs',
    'GetListingPackageAgreementsFilterArgs',
    'GetListingPackagesFilterArgs',
    'GetListingTaxesFilterArgs',
    'GetListingsFilterArgs',
    'GetPublicationPackagesFilterArgs',
    'GetPublicationsFilterArgs',
    'GetPublishersFilterArgs',
]

@pulumi.input_type
class PublicationIconArgs:
    def __init__(__self__, *,
                 content_url: Optional[pulumi.Input[str]] = None,
                 file_extension: Optional[pulumi.Input[str]] = None,
                 mime_type: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] content_url: The content URL of the upload data.
        :param pulumi.Input[str] file_extension: The file extension of the upload data.
        :param pulumi.Input[str] mime_type: The MIME type of the upload data.
        :param pulumi.Input[str] name: (Updatable) The name of the contact.
        """
        if content_url is not None:
            pulumi.set(__self__, "content_url", content_url)
        if file_extension is not None:
            pulumi.set(__self__, "file_extension", file_extension)
        if mime_type is not None:
            pulumi.set(__self__, "mime_type", mime_type)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter(name="contentUrl")
    def content_url(self) -> Optional[pulumi.Input[str]]:
        """
        The content URL of the upload data.
        """
        return pulumi.get(self, "content_url")

    @content_url.setter
    def content_url(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "content_url", value)

    @property
    @pulumi.getter(name="fileExtension")
    def file_extension(self) -> Optional[pulumi.Input[str]]:
        """
        The file extension of the upload data.
        """
        return pulumi.get(self, "file_extension")

    @file_extension.setter
    def file_extension(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "file_extension", value)

    @property
    @pulumi.getter(name="mimeType")
    def mime_type(self) -> Optional[pulumi.Input[str]]:
        """
        The MIME type of the upload data.
        """
        return pulumi.get(self, "mime_type")

    @mime_type.setter
    def mime_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "mime_type", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The name of the contact.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)


@pulumi.input_type
class PublicationPackageDetailsArgs:
    def __init__(__self__, *,
                 eulas: pulumi.Input[Sequence[pulumi.Input['PublicationPackageDetailsEulaArgs']]],
                 operating_system: pulumi.Input['PublicationPackageDetailsOperatingSystemArgs'],
                 package_type: pulumi.Input[str],
                 package_version: pulumi.Input[str],
                 image_id: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[Sequence[pulumi.Input['PublicationPackageDetailsEulaArgs']]] eulas: End User License Agreeement that a consumer of this listing has to accept
        :param pulumi.Input['PublicationPackageDetailsOperatingSystemArgs'] operating_system: OS used by the listing.
        :param pulumi.Input[str] package_type: Type of the artifact of the listing
        :param pulumi.Input[str] package_version: The version of the package
        :param pulumi.Input[str] image_id: base image id of the listing
        """
        pulumi.set(__self__, "eulas", eulas)
        pulumi.set(__self__, "operating_system", operating_system)
        pulumi.set(__self__, "package_type", package_type)
        pulumi.set(__self__, "package_version", package_version)
        if image_id is not None:
            pulumi.set(__self__, "image_id", image_id)

    @property
    @pulumi.getter
    def eulas(self) -> pulumi.Input[Sequence[pulumi.Input['PublicationPackageDetailsEulaArgs']]]:
        """
        End User License Agreeement that a consumer of this listing has to accept
        """
        return pulumi.get(self, "eulas")

    @eulas.setter
    def eulas(self, value: pulumi.Input[Sequence[pulumi.Input['PublicationPackageDetailsEulaArgs']]]):
        pulumi.set(self, "eulas", value)

    @property
    @pulumi.getter(name="operatingSystem")
    def operating_system(self) -> pulumi.Input['PublicationPackageDetailsOperatingSystemArgs']:
        """
        OS used by the listing.
        """
        return pulumi.get(self, "operating_system")

    @operating_system.setter
    def operating_system(self, value: pulumi.Input['PublicationPackageDetailsOperatingSystemArgs']):
        pulumi.set(self, "operating_system", value)

    @property
    @pulumi.getter(name="packageType")
    def package_type(self) -> pulumi.Input[str]:
        """
        Type of the artifact of the listing
        """
        return pulumi.get(self, "package_type")

    @package_type.setter
    def package_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "package_type", value)

    @property
    @pulumi.getter(name="packageVersion")
    def package_version(self) -> pulumi.Input[str]:
        """
        The version of the package
        """
        return pulumi.get(self, "package_version")

    @package_version.setter
    def package_version(self, value: pulumi.Input[str]):
        pulumi.set(self, "package_version", value)

    @property
    @pulumi.getter(name="imageId")
    def image_id(self) -> Optional[pulumi.Input[str]]:
        """
        base image id of the listing
        """
        return pulumi.get(self, "image_id")

    @image_id.setter
    def image_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "image_id", value)


@pulumi.input_type
class PublicationPackageDetailsEulaArgs:
    def __init__(__self__, *,
                 eula_type: pulumi.Input[str],
                 license_text: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] eula_type: the specified eula's type
        :param pulumi.Input[str] license_text: text of the eula
        """
        pulumi.set(__self__, "eula_type", eula_type)
        if license_text is not None:
            pulumi.set(__self__, "license_text", license_text)

    @property
    @pulumi.getter(name="eulaType")
    def eula_type(self) -> pulumi.Input[str]:
        """
        the specified eula's type
        """
        return pulumi.get(self, "eula_type")

    @eula_type.setter
    def eula_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "eula_type", value)

    @property
    @pulumi.getter(name="licenseText")
    def license_text(self) -> Optional[pulumi.Input[str]]:
        """
        text of the eula
        """
        return pulumi.get(self, "license_text")

    @license_text.setter
    def license_text(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "license_text", value)


@pulumi.input_type
class PublicationPackageDetailsOperatingSystemArgs:
    def __init__(__self__, *,
                 name: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] name: (Updatable) The name of the contact.
        """
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The name of the contact.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)


@pulumi.input_type
class PublicationSupportContactArgs:
    def __init__(__self__, *,
                 email: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 phone: Optional[pulumi.Input[str]] = None,
                 subject: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] email: (Updatable) The email of the contact.
        :param pulumi.Input[str] name: (Updatable) The name of the contact.
        :param pulumi.Input[str] phone: (Updatable) The phone number of the contact.
        :param pulumi.Input[str] subject: (Updatable) The email subject line to use when contacting support.
        """
        if email is not None:
            pulumi.set(__self__, "email", email)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if phone is not None:
            pulumi.set(__self__, "phone", phone)
        if subject is not None:
            pulumi.set(__self__, "subject", subject)

    @property
    @pulumi.getter
    def email(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The email of the contact.
        """
        return pulumi.get(self, "email")

    @email.setter
    def email(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "email", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The name of the contact.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def phone(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The phone number of the contact.
        """
        return pulumi.get(self, "phone")

    @phone.setter
    def phone(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "phone", value)

    @property
    @pulumi.getter
    def subject(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The email subject line to use when contacting support.
        """
        return pulumi.get(self, "subject")

    @subject.setter
    def subject(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "subject", value)


@pulumi.input_type
class PublicationSupportedOperatingSystemArgs:
    def __init__(__self__, *,
                 name: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] name: (Updatable) The name of the contact.
        """
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The name of the contact.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)


@pulumi.input_type
class GetAcceptedAgreementsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetCategoriesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: Name of the product category.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Name of the product category.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetListingPackageAgreementsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetListingPackagesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the variable.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the variable.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetListingTaxesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: Name of the tax code.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Name of the tax code.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetListingsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the listing.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the listing.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetPublicationPackagesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the variable.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the variable.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetPublicationsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the listing.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the listing.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetPublishersFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the publisher.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the publisher.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


