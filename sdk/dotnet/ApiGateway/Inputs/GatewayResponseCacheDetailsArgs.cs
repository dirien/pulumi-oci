// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class GatewayResponseCacheDetailsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Vault Service secret resource.
        /// </summary>
        [Input("authenticationSecretId")]
        public Input<string>? AuthenticationSecretId { get; set; }

        /// <summary>
        /// (Updatable) The version number of the authentication secret to use.
        /// </summary>
        [Input("authenticationSecretVersionNumber")]
        public Input<string>? AuthenticationSecretVersionNumber { get; set; }

        /// <summary>
        /// (Updatable) Defines the timeout for establishing a connection with the Response Cache.
        /// </summary>
        [Input("connectTimeoutInMs")]
        public Input<int>? ConnectTimeoutInMs { get; set; }

        /// <summary>
        /// (Updatable) Defines if the connection should be over SSL.
        /// </summary>
        [Input("isSslEnabled")]
        public Input<bool>? IsSslEnabled { get; set; }

        /// <summary>
        /// (Updatable) Defines whether or not to uphold SSL verification.
        /// </summary>
        [Input("isSslVerifyDisabled")]
        public Input<bool>? IsSslVerifyDisabled { get; set; }

        /// <summary>
        /// (Updatable) Defines the timeout for reading data from the Response Cache.
        /// </summary>
        [Input("readTimeoutInMs")]
        public Input<int>? ReadTimeoutInMs { get; set; }

        /// <summary>
        /// (Updatable) Defines the timeout for transmitting data to the Response Cache.
        /// </summary>
        [Input("sendTimeoutInMs")]
        public Input<int>? SendTimeoutInMs { get; set; }

        [Input("servers")]
        private InputList<Inputs.GatewayResponseCacheDetailsServerArgs>? _servers;

        /// <summary>
        /// (Updatable) The set of cache store members to connect to. At present only a single server is supported.
        /// </summary>
        public InputList<Inputs.GatewayResponseCacheDetailsServerArgs> Servers
        {
            get => _servers ?? (_servers = new InputList<Inputs.GatewayResponseCacheDetailsServerArgs>());
            set => _servers = value;
        }

        /// <summary>
        /// (Updatable) Type of the Response Cache.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public GatewayResponseCacheDetailsArgs()
        {
        }
    }
}
