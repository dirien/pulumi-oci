# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetConfigurationResult',
    'AwaitableGetConfigurationResult',
    'get_configuration',
]

@pulumi.output_type
class GetConfigurationResult:
    """
    A collection of values returned by getConfiguration.
    """
    def __init__(__self__, compartment_id=None, id=None, retention_period_days=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if retention_period_days and not isinstance(retention_period_days, int):
            raise TypeError("Expected argument 'retention_period_days' to be a int")
        pulumi.set(__self__, "retention_period_days", retention_period_days)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="retentionPeriodDays")
    def retention_period_days(self) -> int:
        """
        The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
        """
        return pulumi.get(self, "retention_period_days")


class AwaitableGetConfigurationResult(GetConfigurationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetConfigurationResult(
            compartment_id=self.compartment_id,
            id=self.id,
            retention_period_days=self.retention_period_days)


def get_configuration(compartment_id: Optional[str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetConfigurationResult:
    """
    This data source provides details about a specific Configuration resource in Oracle Cloud Infrastructure Audit service.

    Get the configuration

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_configuration = oci.audit.get_configuration(compartment_id=var["tenancy_ocid"])
    ```


    :param str compartment_id: ID of the root compartment (tenancy)
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:audit/getConfiguration:getConfiguration', __args__, opts=opts, typ=GetConfigurationResult).value

    return AwaitableGetConfigurationResult(
        compartment_id=__ret__.compartment_id,
        id=__ret__.id,
        retention_period_days=__ret__.retention_period_days)
