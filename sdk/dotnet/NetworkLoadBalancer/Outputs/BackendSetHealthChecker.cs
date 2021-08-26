// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer.Outputs
{

    [OutputType]
    public sealed class BackendSetHealthChecker
    {
        /// <summary>
        /// (Updatable) The interval between health checks, in milliseconds. The default value is 10000 (10 seconds).  Example: `10000`
        /// </summary>
        public readonly int? IntervalInMillis;
        /// <summary>
        /// (Updatable) The backend server port against which to run the health check. If the port is not specified, then the network load balancer uses the port information from the `Backend` object. The port must be specified if the backend port is 0.  Example: `8080`
        /// </summary>
        public readonly int? Port;
        /// <summary>
        /// (Updatable) The protocol the health check must use; either HTTP or HTTPS, or UDP or TCP.  Example: `HTTP`
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// (Updatable) Base64 encoded pattern to be sent as UDP or TCP health check probe.
        /// </summary>
        public readonly string? RequestData;
        /// <summary>
        /// (Updatable) A regular expression for parsing the response body from the backend server.  Example: `^((?!false).|\s)*$`
        /// </summary>
        public readonly string? ResponseBodyRegex;
        /// <summary>
        /// (Updatable) Base64 encoded pattern to be validated as UDP or TCP health check probe response.
        /// </summary>
        public readonly string? ResponseData;
        /// <summary>
        /// (Updatable) The number of retries to attempt before a backend server is considered "unhealthy". This number also applies when recovering a server to the "healthy" state. The default value is 3.  Example: `3`
        /// </summary>
        public readonly int? Retries;
        /// <summary>
        /// (Updatable) The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, then you can use common HTTP status codes such as "200".  Example: `200`
        /// </summary>
        public readonly int? ReturnCode;
        /// <summary>
        /// (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. The default value is 3000 (3 seconds).  Example: `3000`
        /// </summary>
        public readonly int? TimeoutInMillis;
        /// <summary>
        /// (Updatable) The path against which to run the health check.  Example: `/healthcheck`
        /// </summary>
        public readonly string? UrlPath;

        [OutputConstructor]
        private BackendSetHealthChecker(
            int? intervalInMillis,

            int? port,

            string protocol,

            string? requestData,

            string? responseBodyRegex,

            string? responseData,

            int? retries,

            int? returnCode,

            int? timeoutInMillis,

            string? urlPath)
        {
            IntervalInMillis = intervalInMillis;
            Port = port;
            Protocol = protocol;
            RequestData = requestData;
            ResponseBodyRegex = responseBodyRegex;
            ResponseData = responseData;
            Retries = retries;
            ReturnCode = returnCode;
            TimeoutInMillis = timeoutInMillis;
            UrlPath = urlPath;
        }
    }
}
