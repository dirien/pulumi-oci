# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'LogAnalyticsObjectCollectionRuleOverrideArgs',
    'GetLogAnalyticsEntitiesFilterArgs',
    'GetLogAnalyticsLogGroupsFilterArgs',
    'GetLogAnalyticsObjectCollectionRulesFilterArgs',
    'GetNamespacesFilterArgs',
]

@pulumi.input_type
class LogAnalyticsObjectCollectionRuleOverrideArgs:
    def __init__(__self__, *,
                 match_type: Optional[pulumi.Input[str]] = None,
                 match_value: Optional[pulumi.Input[str]] = None,
                 property_name: Optional[pulumi.Input[str]] = None,
                 property_value: Optional[pulumi.Input[str]] = None):
        if match_type is not None:
            pulumi.set(__self__, "match_type", match_type)
        if match_value is not None:
            pulumi.set(__self__, "match_value", match_value)
        if property_name is not None:
            pulumi.set(__self__, "property_name", property_name)
        if property_value is not None:
            pulumi.set(__self__, "property_value", property_value)

    @property
    @pulumi.getter(name="matchType")
    def match_type(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "match_type")

    @match_type.setter
    def match_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "match_type", value)

    @property
    @pulumi.getter(name="matchValue")
    def match_value(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "match_value")

    @match_value.setter
    def match_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "match_value", value)

    @property
    @pulumi.getter(name="propertyName")
    def property_name(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "property_name")

    @property_name.setter
    def property_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "property_name", value)

    @property
    @pulumi.getter(name="propertyValue")
    def property_value(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "property_value")

    @property_value.setter
    def property_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "property_value", value)


@pulumi.input_type
class GetLogAnalyticsEntitiesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to return only log analytics entities whose name matches the entire name given. The match is case-insensitive.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return only log analytics entities whose name matches the entire name given. The match is case-insensitive.
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
class GetLogAnalyticsLogGroupsFilterArgs:
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
class GetLogAnalyticsObjectCollectionRulesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to return rules only matching with this name.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return rules only matching with this name.
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
class GetNamespacesFilterArgs:
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


