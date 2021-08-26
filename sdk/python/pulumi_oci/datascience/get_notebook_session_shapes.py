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
    'GetNotebookSessionShapesResult',
    'AwaitableGetNotebookSessionShapesResult',
    'get_notebook_session_shapes',
]

@pulumi.output_type
class GetNotebookSessionShapesResult:
    """
    A collection of values returned by getNotebookSessionShapes.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, notebook_session_shapes=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if notebook_session_shapes and not isinstance(notebook_session_shapes, list):
            raise TypeError("Expected argument 'notebook_session_shapes' to be a list")
        pulumi.set(__self__, "notebook_session_shapes", notebook_session_shapes)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNotebookSessionShapesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="notebookSessionShapes")
    def notebook_session_shapes(self) -> Sequence['outputs.GetNotebookSessionShapesNotebookSessionShapeResult']:
        """
        The list of notebook_session_shapes.
        """
        return pulumi.get(self, "notebook_session_shapes")


class AwaitableGetNotebookSessionShapesResult(GetNotebookSessionShapesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNotebookSessionShapesResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            notebook_session_shapes=self.notebook_session_shapes)


def get_notebook_session_shapes(compartment_id: Optional[str] = None,
                                filters: Optional[Sequence[pulumi.InputType['GetNotebookSessionShapesFilterArgs']]] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNotebookSessionShapesResult:
    """
    This data source provides the list of Notebook Session Shapes in Oracle Cloud Infrastructure Data Science service.

    Lists the valid notebook session shapes.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_notebook_session_shapes = oci.datascience.get_notebook_session_shapes(compartment_id=var["compartment_id"])
    ```


    :param str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:datascience/getNotebookSessionShapes:getNotebookSessionShapes', __args__, opts=opts, typ=GetNotebookSessionShapesResult).value

    return AwaitableGetNotebookSessionShapesResult(
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        notebook_session_shapes=__ret__.notebook_session_shapes)
