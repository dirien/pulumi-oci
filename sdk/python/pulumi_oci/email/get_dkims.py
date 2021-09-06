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
    'GetDkimsResult',
    'AwaitableGetDkimsResult',
    'get_dkims',
]

@pulumi.output_type
class GetDkimsResult:
    """
    A collection of values returned by getDkims.
    """
    def __init__(__self__, dkim_collections=None, email_domain_id=None, filters=None, id=None, name=None, state=None):
        if dkim_collections and not isinstance(dkim_collections, list):
            raise TypeError("Expected argument 'dkim_collections' to be a list")
        pulumi.set(__self__, "dkim_collections", dkim_collections)
        if email_domain_id and not isinstance(email_domain_id, str):
            raise TypeError("Expected argument 'email_domain_id' to be a str")
        pulumi.set(__self__, "email_domain_id", email_domain_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="dkimCollections")
    def dkim_collections(self) -> Sequence['outputs.GetDkimsDkimCollectionResult']:
        """
        The list of dkim_collection.
        """
        return pulumi.get(self, "dkim_collections")

    @property
    @pulumi.getter(name="emailDomainId")
    def email_domain_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain that this DKIM belongs to.
        """
        return pulumi.get(self, "email_domain_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDkimsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The DKIM selector. If the same domain is managed in more than one region, each region must use different selectors.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the DKIM.
        """
        return pulumi.get(self, "state")


class AwaitableGetDkimsResult(GetDkimsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDkimsResult(
            dkim_collections=self.dkim_collections,
            email_domain_id=self.email_domain_id,
            filters=self.filters,
            id=self.id,
            name=self.name,
            state=self.state)


def get_dkims(email_domain_id: Optional[str] = None,
              filters: Optional[Sequence[pulumi.InputType['GetDkimsFilterArgs']]] = None,
              id: Optional[str] = None,
              name: Optional[str] = None,
              state: Optional[str] = None,
              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDkimsResult:
    """
    This data source provides the list of Dkims in Oracle Cloud Infrastructure Email service.

    Lists DKIMs for a email domain.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_dkims = oci.email.get_dkims(email_domain_id=oci_email_email_domain["test_email_domain"]["id"],
        id=var["dkim_id"],
        name=var["dkim_name"],
        state=var["dkim_state"])
    ```


    :param str email_domain_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain to which this DKIM belongs.
    :param str id: A filter to only return resources that match the given id exactly.
    :param str name: A filter to only return resources that match the given name exactly.
    :param str state: Filter returned list by specified lifecycle state. This parameter is case-insensitive.
    """
    __args__ = dict()
    __args__['emailDomainId'] = email_domain_id
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['name'] = name
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:email/getDkims:getDkims', __args__, opts=opts, typ=GetDkimsResult).value

    return AwaitableGetDkimsResult(
        dkim_collections=__ret__.dkim_collections,
        email_domain_id=__ret__.email_domain_id,
        filters=__ret__.filters,
        id=__ret__.id,
        name=__ret__.name,
        state=__ret__.state)
