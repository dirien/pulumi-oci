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
    'GetAuthTokensResult',
    'AwaitableGetAuthTokensResult',
    'get_auth_tokens',
]

@pulumi.output_type
class GetAuthTokensResult:
    """
    A collection of values returned by getAuthTokens.
    """
    def __init__(__self__, filters=None, id=None, tokens=None, user_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if tokens and not isinstance(tokens, list):
            raise TypeError("Expected argument 'tokens' to be a list")
        pulumi.set(__self__, "tokens", tokens)
        if user_id and not isinstance(user_id, str):
            raise TypeError("Expected argument 'user_id' to be a str")
        pulumi.set(__self__, "user_id", user_id)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAuthTokensFilterResult']]:
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
    def tokens(self) -> Sequence['outputs.GetAuthTokensTokenResult']:
        """
        The list of tokens.
        """
        return pulumi.get(self, "tokens")

    @property
    @pulumi.getter(name="userId")
    def user_id(self) -> str:
        """
        The OCID of the user the auth token belongs to.
        """
        return pulumi.get(self, "user_id")


class AwaitableGetAuthTokensResult(GetAuthTokensResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAuthTokensResult(
            filters=self.filters,
            id=self.id,
            tokens=self.tokens,
            user_id=self.user_id)


def get_auth_tokens(filters: Optional[Sequence[pulumi.InputType['GetAuthTokensFilterArgs']]] = None,
                    user_id: Optional[str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAuthTokensResult:
    """
    This data source provides the list of Auth Tokens in Oracle Cloud Infrastructure Identity service.

    Lists the auth tokens for the specified user. The returned object contains the token's OCID, but not
    the token itself. The actual token is returned only upon creation.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_auth_tokens = oci.identity.get_auth_tokens(user_id=oci_identity_user["test_user"]["id"])
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
    __ret__ = pulumi.runtime.invoke('oci:identity/getAuthTokens:getAuthTokens', __args__, opts=opts, typ=GetAuthTokensResult).value

    return AwaitableGetAuthTokensResult(
        filters=__ret__.filters,
        id=__ret__.id,
        tokens=__ret__.tokens,
        user_id=__ret__.user_id)
