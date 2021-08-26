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
    'GetProjectsResult',
    'AwaitableGetProjectsResult',
    'get_projects',
]

@pulumi.output_type
class GetProjectsResult:
    """
    A collection of values returned by getProjects.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, name=None, project_collections=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if project_collections and not isinstance(project_collections, list):
            raise TypeError("Expected argument 'project_collections' to be a list")
        pulumi.set(__self__, "project_collections", project_collections)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment where the project is created.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetProjectsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        Project name (case-sensitive).
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="projectCollections")
    def project_collections(self) -> Sequence['outputs.GetProjectsProjectCollectionResult']:
        """
        The list of project_collection.
        """
        return pulumi.get(self, "project_collections")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the project.
        """
        return pulumi.get(self, "state")


class AwaitableGetProjectsResult(GetProjectsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetProjectsResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            name=self.name,
            project_collections=self.project_collections,
            state=self.state)


def get_projects(compartment_id: Optional[str] = None,
                 filters: Optional[Sequence[pulumi.InputType['GetProjectsFilterArgs']]] = None,
                 id: Optional[str] = None,
                 name: Optional[str] = None,
                 state: Optional[str] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetProjectsResult:
    """
    This data source provides the list of Projects in Oracle Cloud Infrastructure Devops service.

    Returns a list of projects.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_projects = oci.devops.get_projects(compartment_id=var["compartment_id"],
        id=var["project_id"],
        name=var["project_name"],
        state=var["project_state"])
    ```


    :param str compartment_id: The OCID of the compartment in which to list resources.
    :param str id: Unique identifier or OCID for listing a single resource by ID.
    :param str name: A filter to return only resources that match the entire name given.
    :param str state: A filter to return only Projects that matches the given lifecycleState.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['name'] = name
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:devops/getProjects:getProjects', __args__, opts=opts, typ=GetProjectsResult).value

    return AwaitableGetProjectsResult(
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        name=__ret__.name,
        project_collections=__ret__.project_collections,
        state=__ret__.state)
