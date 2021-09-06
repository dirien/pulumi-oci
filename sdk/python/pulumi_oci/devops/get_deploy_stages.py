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
    'GetDeployStagesResult',
    'AwaitableGetDeployStagesResult',
    'get_deploy_stages',
]

@pulumi.output_type
class GetDeployStagesResult:
    """
    A collection of values returned by getDeployStages.
    """
    def __init__(__self__, compartment_id=None, deploy_pipeline_id=None, deploy_stage_collections=None, display_name=None, filters=None, id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if deploy_pipeline_id and not isinstance(deploy_pipeline_id, str):
            raise TypeError("Expected argument 'deploy_pipeline_id' to be a str")
        pulumi.set(__self__, "deploy_pipeline_id", deploy_pipeline_id)
        if deploy_stage_collections and not isinstance(deploy_stage_collections, list):
            raise TypeError("Expected argument 'deploy_stage_collections' to be a list")
        pulumi.set(__self__, "deploy_stage_collections", deploy_stage_collections)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[str]:
        """
        The OCID of a compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="deployPipelineId")
    def deploy_pipeline_id(self) -> Optional[str]:
        """
        The OCID of a pipeline.
        """
        return pulumi.get(self, "deploy_pipeline_id")

    @property
    @pulumi.getter(name="deployStageCollections")
    def deploy_stage_collections(self) -> Sequence['outputs.GetDeployStagesDeployStageCollectionResult']:
        """
        The list of deploy_stage_collection.
        """
        return pulumi.get(self, "deploy_stage_collections")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        Deployment stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDeployStagesFilterResult']]:
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
    def state(self) -> Optional[str]:
        """
        The current state of the deployment stage.
        """
        return pulumi.get(self, "state")


class AwaitableGetDeployStagesResult(GetDeployStagesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeployStagesResult(
            compartment_id=self.compartment_id,
            deploy_pipeline_id=self.deploy_pipeline_id,
            deploy_stage_collections=self.deploy_stage_collections,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            state=self.state)


def get_deploy_stages(compartment_id: Optional[str] = None,
                      deploy_pipeline_id: Optional[str] = None,
                      display_name: Optional[str] = None,
                      filters: Optional[Sequence[pulumi.InputType['GetDeployStagesFilterArgs']]] = None,
                      id: Optional[str] = None,
                      state: Optional[str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeployStagesResult:
    """
    This data source provides the list of Deploy Stages in Oracle Cloud Infrastructure Devops service.

    Retrieves a list of deployment stages.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deploy_stages = oci.devops.get_deploy_stages(compartment_id=var["compartment_id"],
        deploy_pipeline_id=oci_devops_deploy_pipeline["test_deploy_pipeline"]["id"],
        display_name=var["deploy_stage_display_name"],
        id=var["deploy_stage_id"],
        state=var["deploy_stage_state"])
    ```


    :param str compartment_id: The OCID of the compartment in which to list resources.
    :param str deploy_pipeline_id: The ID of the parent pipeline.
    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str id: Unique identifier or OCID for listing a single resource by ID.
    :param str state: A filter to return only deployment stages that matches the given lifecycle state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['deployPipelineId'] = deploy_pipeline_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:devops/getDeployStages:getDeployStages', __args__, opts=opts, typ=GetDeployStagesResult).value

    return AwaitableGetDeployStagesResult(
        compartment_id=__ret__.compartment_id,
        deploy_pipeline_id=__ret__.deploy_pipeline_id,
        deploy_stage_collections=__ret__.deploy_stage_collections,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        state=__ret__.state)
