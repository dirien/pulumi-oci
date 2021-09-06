# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetAddressListResult',
    'AwaitableGetAddressListResult',
    'get_address_list',
]

@pulumi.output_type
class GetAddressListResult:
    """
    A collection of values returned by getAddressList.
    """
    def __init__(__self__, address_count=None, address_list_id=None, addresses=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, state=None, time_created=None):
        if address_count and not isinstance(address_count, float):
            raise TypeError("Expected argument 'address_count' to be a float")
        pulumi.set(__self__, "address_count", address_count)
        if address_list_id and not isinstance(address_list_id, str):
            raise TypeError("Expected argument 'address_list_id' to be a str")
        pulumi.set(__self__, "address_list_id", address_list_id)
        if addresses and not isinstance(addresses, list):
            raise TypeError("Expected argument 'addresses' to be a list")
        pulumi.set(__self__, "addresses", addresses)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="addressCount")
    def address_count(self) -> float:
        """
        The total number of unique IP addresses in the address list.
        """
        return pulumi.get(self, "address_count")

    @property
    @pulumi.getter(name="addressListId")
    def address_list_id(self) -> str:
        return pulumi.get(self, "address_list_id")

    @property
    @pulumi.getter
    def addresses(self) -> Sequence[str]:
        """
        The list of IP addresses or CIDR notations.
        """
        return pulumi.get(self, "addresses")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the address list's compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The user-friendly name of the address list.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the address list.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current lifecycle state of the address list.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the address list was created, expressed in RFC 3339 timestamp format.
        """
        return pulumi.get(self, "time_created")


class AwaitableGetAddressListResult(GetAddressListResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAddressListResult(
            address_count=self.address_count,
            address_list_id=self.address_list_id,
            addresses=self.addresses,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            state=self.state,
            time_created=self.time_created)


def get_address_list(address_list_id: Optional[str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAddressListResult:
    """
    This data source provides details about a specific Address List resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.

    Gets the details of an address list.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_address_list = oci.waas.get_address_list(address_list_id=oci_waas_address_list["test_address_list"]["id"])
    ```


    :param str address_list_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the address list. This number is generated when the address list is added to the compartment.
    """
    __args__ = dict()
    __args__['addressListId'] = address_list_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:waas/getAddressList:getAddressList', __args__, opts=opts, typ=GetAddressListResult).value

    return AwaitableGetAddressListResult(
        address_count=__ret__.address_count,
        address_list_id=__ret__.address_list_id,
        addresses=__ret__.addresses,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        state=__ret__.state,
        time_created=__ret__.time_created)
