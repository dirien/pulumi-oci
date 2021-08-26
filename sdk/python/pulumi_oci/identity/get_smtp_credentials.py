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
    'GetSmtpCredentialsResult',
    'AwaitableGetSmtpCredentialsResult',
    'get_smtp_credentials',
]

@pulumi.output_type
class GetSmtpCredentialsResult:
    """
    A collection of values returned by getSmtpCredentials.
    """
    def __init__(__self__, filters=None, id=None, smtp_credentials=None, user_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if smtp_credentials and not isinstance(smtp_credentials, list):
            raise TypeError("Expected argument 'smtp_credentials' to be a list")
        pulumi.set(__self__, "smtp_credentials", smtp_credentials)
        if user_id and not isinstance(user_id, str):
            raise TypeError("Expected argument 'user_id' to be a str")
        pulumi.set(__self__, "user_id", user_id)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSmtpCredentialsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="smtpCredentials")
    def smtp_credentials(self) -> Sequence['outputs.GetSmtpCredentialsSmtpCredentialResult']:
        """
        The list of smtp_credentials.
        """
        return pulumi.get(self, "smtp_credentials")

    @property
    @pulumi.getter(name="userId")
    def user_id(self) -> str:
        """
        The OCID of the user the SMTP credential belongs to.
        """
        return pulumi.get(self, "user_id")


class AwaitableGetSmtpCredentialsResult(GetSmtpCredentialsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSmtpCredentialsResult(
            filters=self.filters,
            id=self.id,
            smtp_credentials=self.smtp_credentials,
            user_id=self.user_id)


def get_smtp_credentials(filters: Optional[Sequence[pulumi.InputType['GetSmtpCredentialsFilterArgs']]] = None,
                         user_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSmtpCredentialsResult:
    """
    This data source provides the list of Smtp Credentials in Oracle Cloud Infrastructure Identity service.

    Lists the SMTP credentials for the specified user. The returned object contains the credential's OCID,
    the SMTP user name but not the SMTP password. The SMTP password is returned only upon creation.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_smtp_credentials = oci.identity.get_smtp_credentials(user_id=oci_identity_user["test_user"]["id"])
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
    __ret__ = pulumi.runtime.invoke('oci:identity/getSmtpCredentials:getSmtpCredentials', __args__, opts=opts, typ=GetSmtpCredentialsResult).value

    return AwaitableGetSmtpCredentialsResult(
        filters=__ret__.filters,
        id=__ret__.id,
        smtp_credentials=__ret__.smtp_credentials,
        user_id=__ret__.user_id)
