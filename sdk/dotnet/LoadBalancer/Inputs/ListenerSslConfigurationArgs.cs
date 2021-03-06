// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Inputs
{

    public sealed class ListenerSslConfigurationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        /// </summary>
        [Input("certificateName", required: true)]
        public Input<string> CertificateName { get; set; } = null!;

        /// <summary>
        /// (Updatable) The name of the cipher suite to use for HTTPS or SSL connections.
        /// </summary>
        [Input("cipherSuiteName")]
        public Input<string>? CipherSuiteName { get; set; }

        [Input("protocols")]
        private InputList<string>? _protocols;

        /// <summary>
        /// (Updatable) A list of SSL protocols the load balancer must support for HTTPS or SSL connections.
        /// </summary>
        public InputList<string> Protocols
        {
            get => _protocols ?? (_protocols = new InputList<string>());
            set => _protocols = value;
        }

        /// <summary>
        /// (Updatable) When this attribute is set to ENABLED, the system gives preference to the server ciphers over the client ciphers.
        /// </summary>
        [Input("serverOrderPreference")]
        public Input<string>? ServerOrderPreference { get; set; }

        /// <summary>
        /// (Updatable) The maximum depth for peer certificate chain verification.  Example: `3`
        /// </summary>
        [Input("verifyDepth")]
        public Input<int>? VerifyDepth { get; set; }

        /// <summary>
        /// (Updatable) Whether the load balancer listener should verify peer certificates.  Example: `true`
        /// </summary>
        [Input("verifyPeerCertificate")]
        public Input<bool>? VerifyPeerCertificate { get; set; }

        public ListenerSslConfigurationArgs()
        {
        }
    }
}
