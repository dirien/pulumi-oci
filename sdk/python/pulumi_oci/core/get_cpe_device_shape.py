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
    'GetCpeDeviceShapeResult',
    'AwaitableGetCpeDeviceShapeResult',
    'get_cpe_device_shape',
]

@pulumi.output_type
class GetCpeDeviceShapeResult:
    """
    A collection of values returned by getCpeDeviceShape.
    """
    def __init__(__self__, cpe_device_infos=None, cpe_device_shape_id=None, id=None, parameters=None, template=None):
        if cpe_device_infos and not isinstance(cpe_device_infos, list):
            raise TypeError("Expected argument 'cpe_device_infos' to be a list")
        pulumi.set(__self__, "cpe_device_infos", cpe_device_infos)
        if cpe_device_shape_id and not isinstance(cpe_device_shape_id, str):
            raise TypeError("Expected argument 'cpe_device_shape_id' to be a str")
        pulumi.set(__self__, "cpe_device_shape_id", cpe_device_shape_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if parameters and not isinstance(parameters, list):
            raise TypeError("Expected argument 'parameters' to be a list")
        pulumi.set(__self__, "parameters", parameters)
        if template and not isinstance(template, str):
            raise TypeError("Expected argument 'template' to be a str")
        pulumi.set(__self__, "template", template)

    @property
    @pulumi.getter(name="cpeDeviceInfos")
    def cpe_device_infos(self) -> Sequence['outputs.GetCpeDeviceShapeCpeDeviceInfoResult']:
        """
        Basic information about a particular CPE device type.
        """
        return pulumi.get(self, "cpe_device_infos")

    @property
    @pulumi.getter(name="cpeDeviceShapeId")
    def cpe_device_shape_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device shape. This value uniquely identifies the type of CPE device.
        """
        return pulumi.get(self, "cpe_device_shape_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def parameters(self) -> Sequence['outputs.GetCpeDeviceShapeParameterResult']:
        """
        For certain CPE devices types, the customer can provide answers to questions that are specific to the device type. This attribute contains a list of those questions. The Networking service merges the answers with other information and renders a set of CPE configuration content. To provide the answers, use [UpdateTunnelCpeDeviceConfig](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/UpdateTunnelCpeDeviceConfig).
        """
        return pulumi.get(self, "parameters")

    @property
    @pulumi.getter
    def template(self) -> str:
        """
        A template of CPE device configuration information that will be merged with the customer's answers to the questions to render the final CPE device configuration content. Also see:
        * [GetCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/GetCpeDeviceConfigContent)
        * [GetIpsecCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/GetIpsecCpeDeviceConfigContent)
        * [GetTunnelCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/GetTunnelCpeDeviceConfigContent)
        """
        return pulumi.get(self, "template")


class AwaitableGetCpeDeviceShapeResult(GetCpeDeviceShapeResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCpeDeviceShapeResult(
            cpe_device_infos=self.cpe_device_infos,
            cpe_device_shape_id=self.cpe_device_shape_id,
            id=self.id,
            parameters=self.parameters,
            template=self.template)


def get_cpe_device_shape(cpe_device_shape_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCpeDeviceShapeResult:
    """
    This data source provides details about a specific Cpe Device Shape resource in Oracle Cloud Infrastructure Core service.

    Gets the detailed information about the specified CPE device type. This might include a set of questions
    that are specific to the particular CPE device type. The customer must supply answers to those questions
    (see [UpdateTunnelCpeDeviceConfig](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/UpdateTunnelCpeDeviceConfig)).
    The service merges the answers with a template of other information for the CPE device type. The following
    operations return the merged content:

      * [GetCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/GetCpeDeviceConfigContent)
      * [GetIpsecCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/GetIpsecCpeDeviceConfigContent)
      * [GetTunnelCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/GetTunnelCpeDeviceConfigContent)

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cpe_device_shape = oci.core.get_cpe_device_shape(cpe_device_shape_id=oci_core_cpe_device_shape["test_cpe_device_shape"]["id"])
    ```


    :param str cpe_device_shape_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device shape.
    """
    __args__ = dict()
    __args__['cpeDeviceShapeId'] = cpe_device_shape_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getCpeDeviceShape:getCpeDeviceShape', __args__, opts=opts, typ=GetCpeDeviceShapeResult).value

    return AwaitableGetCpeDeviceShapeResult(
        cpe_device_infos=__ret__.cpe_device_infos,
        cpe_device_shape_id=__ret__.cpe_device_shape_id,
        id=__ret__.id,
        parameters=__ret__.parameters,
        template=__ret__.template)
