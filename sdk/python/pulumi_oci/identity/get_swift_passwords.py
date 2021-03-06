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
    'GetSwiftPasswordsResult',
    'AwaitableGetSwiftPasswordsResult',
    'get_swift_passwords',
]

@pulumi.output_type
class GetSwiftPasswordsResult:
    """
    A collection of values returned by getSwiftPasswords.
    """
    def __init__(__self__, filters=None, id=None, passwords=None, user_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if passwords and not isinstance(passwords, list):
            raise TypeError("Expected argument 'passwords' to be a list")
        pulumi.set(__self__, "passwords", passwords)
        if user_id and not isinstance(user_id, str):
            raise TypeError("Expected argument 'user_id' to be a str")
        pulumi.set(__self__, "user_id", user_id)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSwiftPasswordsFilterResult']]:
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
    def passwords(self) -> Sequence['outputs.GetSwiftPasswordsPasswordResult']:
        """
        The list of passwords.
        """
        return pulumi.get(self, "passwords")

    @property
    @pulumi.getter(name="userId")
    def user_id(self) -> str:
        """
        The OCID of the user the password belongs to.
        """
        return pulumi.get(self, "user_id")


class AwaitableGetSwiftPasswordsResult(GetSwiftPasswordsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSwiftPasswordsResult(
            filters=self.filters,
            id=self.id,
            passwords=self.passwords,
            user_id=self.user_id)


def get_swift_passwords(filters: Optional[Sequence[pulumi.InputType['GetSwiftPasswordsFilterArgs']]] = None,
                        user_id: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSwiftPasswordsResult:
    """
    This data source provides the list of Swift Passwords in Oracle Cloud Infrastructure Identity service.

    **Deprecated. Use [ListAuthTokens](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AuthToken/ListAuthTokens) instead.**

    Lists the Swift passwords for the specified user. The returned object contains the password's OCID, but not
    the password itself. The actual password is returned only upon creation.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_swift_passwords = oci.identity.get_swift_passwords(user_id=oci_identity_user["test_user"]["id"])
    ```


    :param str user_id: The OCID of the user.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['userId'] = user_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:identity/getSwiftPasswords:getSwiftPasswords', __args__, opts=opts, typ=GetSwiftPasswordsResult).value

    return AwaitableGetSwiftPasswordsResult(
        filters=__ret__.filters,
        id=__ret__.id,
        passwords=__ret__.passwords,
        user_id=__ret__.user_id)
