// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class WaasPolicyOriginArgs : Pulumi.ResourceArgs
    {
        [Input("customHeaders")]
        private InputList<Inputs.WaasPolicyOriginCustomHeaderArgs>? _customHeaders;

        /// <summary>
        /// (Updatable) A list of HTTP headers to forward to your origin.
        /// </summary>
        public InputList<Inputs.WaasPolicyOriginCustomHeaderArgs> CustomHeaders
        {
            get => _customHeaders ?? (_customHeaders = new InputList<Inputs.WaasPolicyOriginCustomHeaderArgs>());
            set => _customHeaders = value;
        }

        /// <summary>
        /// (Updatable) The HTTP port on the origin that the web application listens on. If unspecified, defaults to `80`. If `0` is specified - the origin is not used for HTTP traffic.
        /// </summary>
        [Input("httpPort")]
        public Input<int>? HttpPort { get; set; }

        /// <summary>
        /// (Updatable) The HTTPS port on the origin that the web application listens on. If unspecified, defaults to `443`. If `0` is specified - the origin is not used for HTTPS traffic.
        /// </summary>
        [Input("httpsPort")]
        public Input<int>? HttpsPort { get; set; }

        [Input("label", required: true)]
        public Input<string> Label { get; set; } = null!;

        /// <summary>
        /// (Updatable) The URI of the origin. Does not support paths. Port numbers should be specified in the `httpPort` and `httpsPort` fields.
        /// </summary>
        [Input("uri", required: true)]
        public Input<string> Uri { get; set; } = null!;

        public WaasPolicyOriginArgs()
        {
        }
    }
}
