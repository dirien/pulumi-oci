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
    'GetDbSystemPatchesResult',
    'AwaitableGetDbSystemPatchesResult',
    'get_db_system_patches',
]

@pulumi.output_type
class GetDbSystemPatchesResult:
    """
    A collection of values returned by getDbSystemPatches.
    """
    def __init__(__self__, db_system_id=None, filters=None, id=None, patches=None):
        if db_system_id and not isinstance(db_system_id, str):
            raise TypeError("Expected argument 'db_system_id' to be a str")
        pulumi.set(__self__, "db_system_id", db_system_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if patches and not isinstance(patches, list):
            raise TypeError("Expected argument 'patches' to be a list")
        pulumi.set(__self__, "patches", patches)

    @property
    @pulumi.getter(name="dbSystemId")
    def db_system_id(self) -> str:
        return pulumi.get(self, "db_system_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDbSystemPatchesFilterResult']]:
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
    def patches(self) -> Sequence['outputs.GetDbSystemPatchesPatchResult']:
        """
        The list of patches.
        """
        return pulumi.get(self, "patches")


class AwaitableGetDbSystemPatchesResult(GetDbSystemPatchesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDbSystemPatchesResult(
            db_system_id=self.db_system_id,
            filters=self.filters,
            id=self.id,
            patches=self.patches)


def get_db_system_patches(db_system_id: Optional[str] = None,
                          filters: Optional[Sequence[pulumi.InputType['GetDbSystemPatchesFilterArgs']]] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDbSystemPatchesResult:
    """
    This data source provides the list of Db System Patches in Oracle Cloud Infrastructure Database service.

    Lists the patches applicable to the specified DB system.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_system_patches = oci.database.get_db_system_patches(db_system_id=oci_database_db_system["test_db_system"]["id"])
    ```


    :param str db_system_id: The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['dbSystemId'] = db_system_id
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:database/getDbSystemPatches:getDbSystemPatches', __args__, opts=opts, typ=GetDbSystemPatchesResult).value

    return AwaitableGetDbSystemPatchesResult(
        db_system_id=__ret__.db_system_id,
        filters=__ret__.filters,
        id=__ret__.id,
        patches=__ret__.patches)
