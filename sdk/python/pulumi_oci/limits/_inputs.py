# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetLimitDefinitionsFilterArgs',
    'GetLimitValuesFilterArgs',
    'GetQuotasFilterArgs',
    'GetServicesFilterArgs',
]

@pulumi.input_type
class GetLimitDefinitionsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: Optional field, filter for a specific resource limit.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Optional field, filter for a specific resource limit.
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
class GetLimitValuesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: Optional field, can be used to see a specific resource limit value.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Optional field, can be used to see a specific resource limit value.
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
class GetQuotasFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: name
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        name
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
class GetServicesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The service name. Use this when calling other APIs.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The service name. Use this when calling other APIs.
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


