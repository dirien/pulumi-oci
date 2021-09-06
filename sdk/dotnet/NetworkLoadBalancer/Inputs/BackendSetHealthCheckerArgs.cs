// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer.Inputs
{

    public sealed class BackendSetHealthCheckerArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The interval between health checks, in milliseconds. The default value is 10000 (10 seconds).  Example: `10000`
        /// </summary>
        [Input("intervalInMillis")]
        public Input<int>? IntervalInMillis { get; set; }

        /// <summary>
        /// (Updatable) The backend server port against which to run the health check. If the port is not specified, then the network load balancer uses the port information from the `Backend` object. The port must be specified if the backend port is 0.  Example: `8080`
        /// </summary>
        [Input("port")]
        public Input<int>? Port { get; set; }

        /// <summary>
        /// (Updatable) The protocol the health check must use; either HTTP or HTTPS, or UDP or TCP.  Example: `HTTP`
        /// </summary>
        [Input("protocol", required: true)]
        public Input<string> Protocol { get; set; } = null!;

        /// <summary>
        /// (Updatable) Base64 encoded pattern to be sent as UDP or TCP health check probe.
        /// </summary>
        [Input("requestData")]
        public Input<string>? RequestData { get; set; }

        /// <summary>
        /// (Updatable) A regular expression for parsing the response body from the backend server.  Example: `^((?!false).|\s)*$`
        /// </summary>
        [Input("responseBodyRegex")]
        public Input<string>? ResponseBodyRegex { get; set; }

        /// <summary>
        /// (Updatable) Base64 encoded pattern to be validated as UDP or TCP health check probe response.
        /// </summary>
        [Input("responseData")]
        public Input<string>? ResponseData { get; set; }

        /// <summary>
        /// (Updatable) The number of retries to attempt before a backend server is considered "unhealthy". This number also applies when recovering a server to the "healthy" state. The default value is 3.  Example: `3`
        /// </summary>
        [Input("retries")]
        public Input<int>? Retries { get; set; }

        /// <summary>
        /// (Updatable) The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, then you can use common HTTP status codes such as "200".  Example: `200`
        /// </summary>
        [Input("returnCode")]
        public Input<int>? ReturnCode { get; set; }

        /// <summary>
        /// (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. The default value is 3000 (3 seconds).  Example: `3000`
        /// </summary>
        [Input("timeoutInMillis")]
        public Input<int>? TimeoutInMillis { get; set; }

        /// <summary>
        /// (Updatable) The path against which to run the health check.  Example: `/healthcheck`
        /// </summary>
        [Input("urlPath")]
        public Input<string>? UrlPath { get; set; }

        public BackendSetHealthCheckerArgs()
        {
        }
    }
}
