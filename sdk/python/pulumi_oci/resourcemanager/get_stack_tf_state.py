# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetStackTfStateResult',
    'AwaitableGetStackTfStateResult',
    'get_stack_tf_state',
]

@pulumi.output_type
class GetStackTfStateResult:
    """
    A collection of values returned by getStackTfState.
    """
    def __init__(__self__, id=None, local_path=None, stack_id=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if local_path and not isinstance(local_path, str):
            raise TypeError("Expected argument 'local_path' to be a str")
        pulumi.set(__self__, "local_path", local_path)
        if stack_id and not isinstance(stack_id, str):
            raise TypeError("Expected argument 'stack_id' to be a str")
        pulumi.set(__self__, "stack_id", stack_id)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="localPath")
    def local_path(self) -> str:
        return pulumi.get(self, "local_path")

    @property
    @pulumi.getter(name="stackId")
    def stack_id(self) -> str:
        return pulumi.get(self, "stack_id")


class AwaitableGetStackTfStateResult(GetStackTfStateResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetStackTfStateResult(
            id=self.id,
            local_path=self.local_path,
            stack_id=self.stack_id)


def get_stack_tf_state(local_path: Optional[str] = None,
                       stack_id: Optional[str] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetStackTfStateResult:
    """
    Use this data source to access information about an existing resource.

    :param str stack_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stack.
    """
    __args__ = dict()
    __args__['localPath'] = local_path
    __args__['stackId'] = stack_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:resourcemanager/getStackTfState:getStackTfState', __args__, opts=opts, typ=GetStackTfStateResult).value

    return AwaitableGetStackTfStateResult(
        id=__ret__.id,
        local_path=__ret__.local_path,
        stack_id=__ret__.stack_id)