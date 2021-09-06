// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ClusterEndpointsGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The non-native networking Kubernetes API server endpoint.
        /// </summary>
        [Input("kubernetes")]
        public Input<string>? Kubernetes { get; set; }

        /// <summary>
        /// The private native networking Kubernetes API server endpoint.
        /// </summary>
        [Input("privateEndpoint")]
        public Input<string>? PrivateEndpoint { get; set; }

        /// <summary>
        /// The public native networking Kubernetes API server endpoint, if one was requested.
        /// </summary>
        [Input("publicEndpoint")]
        public Input<string>? PublicEndpoint { get; set; }

        public ClusterEndpointsGetArgs()
        {
        }
    }
}
