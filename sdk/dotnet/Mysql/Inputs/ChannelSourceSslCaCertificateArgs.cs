// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class ChannelSourceSslCaCertificateArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type of CA certificate.
        /// </summary>
        [Input("certificateType", required: true)]
        public Input<string> CertificateType { get; set; } = null!;

        /// <summary>
        /// (Updatable) The string containing the CA certificate in PEM format.
        /// </summary>
        [Input("contents", required: true)]
        public Input<string> Contents { get; set; } = null!;

        public ChannelSourceSslCaCertificateArgs()
        {
        }
    }
}
