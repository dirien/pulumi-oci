# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetNotebookSessionResult',
    'AwaitableGetNotebookSessionResult',
    'get_notebook_session',
]

@pulumi.output_type
class GetNotebookSessionResult:
    """
    A collection of values returned by getNotebookSession.
    """
    def __init__(__self__, compartment_id=None, created_by=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, notebook_session_configuration_details=None, notebook_session_id=None, notebook_session_url=None, project_id=None, state=None, time_created=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
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
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if notebook_session_configuration_details and not isinstance(notebook_session_configuration_details, dict):
            raise TypeError("Expected argument 'notebook_session_configuration_details' to be a dict")
        pulumi.set(__self__, "notebook_session_configuration_details", notebook_session_configuration_details)
        if notebook_session_id and not isinstance(notebook_session_id, str):
            raise TypeError("Expected argument 'notebook_session_id' to be a str")
        pulumi.set(__self__, "notebook_session_id", notebook_session_id)
        if notebook_session_url and not isinstance(notebook_session_url, str):
            raise TypeError("Expected argument 'notebook_session_url' to be a str")
        pulumi.set(__self__, "notebook_session_url", notebook_session_url)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the notebook session's compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the notebook session.
        """
        return pulumi.get(self, "created_by")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My NotebookSession`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the notebook session.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Details about the state of the notebook session.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="notebookSessionConfigurationDetails")
    def notebook_session_configuration_details(self) -> 'outputs.GetNotebookSessionNotebookSessionConfigurationDetailsResult':
        """
        Details for the notebook session configuration.
        """
        return pulumi.get(self, "notebook_session_configuration_details")

    @property
    @pulumi.getter(name="notebookSessionId")
    def notebook_session_id(self) -> str:
        return pulumi.get(self, "notebook_session_id")

    @property
    @pulumi.getter(name="notebookSessionUrl")
    def notebook_session_url(self) -> str:
        """
        The URL to interact with the notebook session.
        """
        return pulumi.get(self, "notebook_session_url")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the notebook session.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The state of the notebook session.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
        """
        return pulumi.get(self, "time_created")


class AwaitableGetNotebookSessionResult(GetNotebookSessionResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNotebookSessionResult(
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            notebook_session_configuration_details=self.notebook_session_configuration_details,
            notebook_session_id=self.notebook_session_id,
            notebook_session_url=self.notebook_session_url,
            project_id=self.project_id,
            state=self.state,
            time_created=self.time_created)


def get_notebook_session(notebook_session_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNotebookSessionResult:
    """
    This data source provides details about a specific Notebook Session resource in Oracle Cloud Infrastructure Data Science service.

    Gets the specified notebook session's information.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_notebook_session = oci.datascience.get_notebook_session(notebook_session_id=oci_datascience_notebook_session["test_notebook_session"]["id"])
    ```


    :param str notebook_session_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the notebook session.
    """
    __args__ = dict()
    __args__['notebookSessionId'] = notebook_session_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:datascience/getNotebookSession:getNotebookSession', __args__, opts=opts, typ=GetNotebookSessionResult).value

    return AwaitableGetNotebookSessionResult(
        compartment_id=__ret__.compartment_id,
        created_by=__ret__.created_by,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        notebook_session_configuration_details=__ret__.notebook_session_configuration_details,
        notebook_session_id=__ret__.notebook_session_id,
        notebook_session_url=__ret__.notebook_session_url,
        project_id=__ret__.project_id,
        state=__ret__.state,
        time_created=__ret__.time_created)
