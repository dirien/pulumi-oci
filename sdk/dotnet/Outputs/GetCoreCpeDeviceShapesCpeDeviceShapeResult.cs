// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetCoreCpeDeviceShapesCpeDeviceShapeResult
    {
        /// <summary>
        /// Basic information about a particular CPE device type.
        /// </summary>
        public readonly Outputs.GetCoreCpeDeviceShapesCpeDeviceShapeCpeDeviceInfoResult CpeDeviceInfo;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device shape. This value uniquely identifies the type of CPE device.
        /// </summary>
        public readonly string CpeDeviceShapeId;
        /// <summary>
        /// A template of CPE device configuration information that will be merged with the customer's answers to the questions to render the final CPE device configuration content. Also see:
        /// * [GetCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/GetCpeDeviceConfigContent)
        /// * [GetIpsecCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/GetIpsecCpeDeviceConfigContent)
        /// * [GetTunnelCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/GetTunnelCpeDeviceConfigContent)
        /// </summary>
        public readonly string Template;

        [OutputConstructor]
        private GetCoreCpeDeviceShapesCpeDeviceShapeResult(
            Outputs.GetCoreCpeDeviceShapesCpeDeviceShapeCpeDeviceInfoResult cpeDeviceInfo,

            string cpeDeviceShapeId,

            string template)
        {
            CpeDeviceInfo = cpeDeviceInfo;
            CpeDeviceShapeId = cpeDeviceShapeId;
            Template = template;
        }
    }
}