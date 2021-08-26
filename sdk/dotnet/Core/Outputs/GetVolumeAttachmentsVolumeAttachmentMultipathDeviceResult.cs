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
    public sealed class GetVolumeAttachmentsVolumeAttachmentMultipathDeviceResult
    {
        /// <summary>
        /// The volume's iSCSI IP address.  Example: `169.254.2.2`
        /// </summary>
        public readonly string Ipv4;
        /// <summary>
        /// The target volume's iSCSI Qualified Name in the format defined by [RFC 3720](https://tools.ietf.org/html/rfc3720#page-32).  Example: `iqn.2015-12.com.oracleiaas:40b7ee03-883f-46c6-a951-63d2841d2195`
        /// </summary>
        public readonly string Iqn;
        /// <summary>
        /// The volume's iSCSI port, usually port 860 or 3260.  Example: `3260`
        /// </summary>
        public readonly int Port;

        [OutputConstructor]
        private GetVolumeAttachmentsVolumeAttachmentMultipathDeviceResult(
            string ipv4,

            string iqn,

            int port)
        {
            Ipv4 = ipv4;
            Iqn = iqn;
            Port = port;
        }
    }
}