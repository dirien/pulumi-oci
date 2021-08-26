// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetCpeDeviceShapesCpeDeviceShapeCpeDeviceInfoResult
    {
        /// <summary>
        /// The platform or software version of the CPE device.
        /// </summary>
        public readonly string PlatformSoftwareVersion;
        /// <summary>
        /// The vendor that makes the CPE device.
        /// </summary>
        public readonly string Vendor;

        [OutputConstructor]
        private GetCpeDeviceShapesCpeDeviceShapeCpeDeviceInfoResult(
            string platformSoftwareVersion,

            string vendor)
        {
            PlatformSoftwareVersion = platformSoftwareVersion;
            Vendor = vendor;
        }
    }
}
