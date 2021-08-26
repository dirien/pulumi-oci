# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetApmDomainsApmDomainResult',
    'GetApmDomainsFilterResult',
    'GetDataKeysDataKeyResult',
    'GetDataKeysFilterResult',
]

@pulumi.output_type
class GetApmDomainsApmDomainResult(dict):
    def __init__(__self__, *,
                 compartment_id: str,
                 data_upload_endpoint: str,
                 defined_tags: Mapping[str, Any],
                 description: str,
                 display_name: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 is_free_tier: bool,
                 state: str,
                 time_created: str,
                 time_updated: str):
        """
        :param str compartment_id: The ID of the compartment in which to list resources.
        :param str data_upload_endpoint: Where APM Agents upload their observations and metrics.
        :param Mapping[str, Any] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param str description: Description of the APM Domain.
        :param str display_name: A filter to return only resources that match the entire display name given.
        :param Mapping[str, Any] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param str id: Unique identifier that is immutable on creation.
        :param bool is_free_tier: Indicates if this is an Always Free resource.
        :param str state: A filter to return only resources that match the given life-cycle state.
        :param str time_created: The time the the APM Domain was created. An RFC3339 formatted datetime string
        :param str time_updated: The time the APM Domain was updated. An RFC3339 formatted datetime string
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "data_upload_endpoint", data_upload_endpoint)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "is_free_tier", is_free_tier)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The ID of the compartment in which to list resources.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="dataUploadEndpoint")
    def data_upload_endpoint(self) -> str:
        """
        Where APM Agents upload their observations and metrics.
        """
        return pulumi.get(self, "data_upload_endpoint")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description of the APM Domain.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A filter to return only resources that match the entire display name given.
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
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isFreeTier")
    def is_free_tier(self) -> bool:
        """
        Indicates if this is an Always Free resource.
        """
        return pulumi.get(self, "is_free_tier")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        A filter to return only resources that match the given life-cycle state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the APM Domain was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the APM Domain was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")


@pulumi.output_type
class GetApmDomainsFilterResult(dict):
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

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetDataKeysDataKeyResult(dict):
    def __init__(__self__, *,
                 name: str,
                 type: str,
                 value: str):
        """
        :param str name: Name of the Data Key. The name uniquely identifies a Data Key within an APM domain.
        :param str type: Type of the Data Key.
        :param str value: Value of the Data Key.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "type", type)
        pulumi.set(__self__, "value", value)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Name of the Data Key. The name uniquely identifies a Data Key within an APM domain.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def type(self) -> str:
        """
        Type of the Data Key.
        """
        return pulumi.get(self, "type")

    @property
    @pulumi.getter
    def value(self) -> str:
        """
        Value of the Data Key.
        """
        return pulumi.get(self, "value")


@pulumi.output_type
class GetDataKeysFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: Name of the Data Key. The name uniquely identifies a Data Key within an APM domain.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Name of the Data Key. The name uniquely identifies a Data Key within an APM domain.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


