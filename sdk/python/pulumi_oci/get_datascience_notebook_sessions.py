# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetDatascienceNotebookSessionsResult',
    'AwaitableGetDatascienceNotebookSessionsResult',
    'get_datascience_notebook_sessions',
]

@pulumi.output_type
class GetDatascienceNotebookSessionsResult:
    """
    A collection of values returned by GetDatascienceNotebookSessions.
    """
    def __init__(__self__, compartment_id=None, created_by=None, display_name=None, filters=None, id=None, notebook_sessions=None, project_id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if notebook_sessions and not isinstance(notebook_sessions, list):
            raise TypeError("Expected argument 'notebook_sessions' to be a list")
        pulumi.set(__self__, "notebook_sessions", notebook_sessions)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the notebook session's compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the notebook session.
        """
        return pulumi.get(self, "created_by")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My NotebookSession`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDatascienceNotebookSessionsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the notebook session.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="notebookSessions")
    def notebook_sessions(self) -> Sequence['outputs.GetDatascienceNotebookSessionsNotebookSessionResult']:
        """
        The list of notebook_sessions.
        """
        return pulumi.get(self, "notebook_sessions")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the notebook session.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The state of the notebook session.
        """
        return pulumi.get(self, "state")


class AwaitableGetDatascienceNotebookSessionsResult(GetDatascienceNotebookSessionsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDatascienceNotebookSessionsResult(
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            notebook_sessions=self.notebook_sessions,
            project_id=self.project_id,
            state=self.state)


def get_datascience_notebook_sessions(compartment_id: Optional[str] = None,
                                      created_by: Optional[str] = None,
                                      display_name: Optional[str] = None,
                                      filters: Optional[Sequence[pulumi.InputType['GetDatascienceNotebookSessionsFilterArgs']]] = None,
                                      id: Optional[str] = None,
                                      project_id: Optional[str] = None,
                                      state: Optional[str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDatascienceNotebookSessionsResult:
    """
    This data source provides the list of Notebook Sessions in Oracle Cloud Infrastructure Data Science service.

    Lists the notebook sessions in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_notebook_sessions = oci.get_datascience_notebook_sessions(compartment_id=var["compartment_id"],
        created_by=var["notebook_session_created_by"],
        display_name=var["notebook_session_display_name"],
        id=var["notebook_session_id"],
        project_id=oci_datascience_project["test_project"]["id"],
        state=var["notebook_session_state"])
    ```


    :param str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str created_by: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
    :param str display_name: <b>Filter</b> results by its user-friendly name.
    :param str id: <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
    :param str project_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
    :param str state: <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['createdBy'] = created_by
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['projectId'] = project_id
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:index/getDatascienceNotebookSessions:GetDatascienceNotebookSessions', __args__, opts=opts, typ=GetDatascienceNotebookSessionsResult).value

    return AwaitableGetDatascienceNotebookSessionsResult(
        compartment_id=__ret__.compartment_id,
        created_by=__ret__.created_by,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        notebook_sessions=__ret__.notebook_sessions,
        project_id=__ret__.project_id,
        state=__ret__.state)