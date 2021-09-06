// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class GetHttpRedirectTargetResult
    {
        /// <summary>
        /// The host portion of the redirect.
        /// </summary>
        public readonly string Host;
        /// <summary>
        /// The path component of the target URL (e.g., "/path/to/resource" in "https://target.example.com/path/to/resource?redirected"), which can be empty, static, or request-copying, or request-prefixing. Use of \ is not permitted except to escape a following \, {, or }. An empty value is treated the same as static "/". A static value must begin with a leading "/", optionally followed by other path characters. A request-copying value must exactly match "{path}", and will be replaced with the path component of the request URL (including its initial "/"). A request-prefixing value must start with "/" and end with a non-escaped "{path}", which will be replaced with the path component of the request URL (including its initial "/"). Only one such replacement token is allowed.
        /// </summary>
        public readonly string Path;
        /// <summary>
        /// Port number of the target destination of the redirect, default to match protocol
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// The protocol used for the target, http or https.
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// The query component of the target URL (e.g., "?redirected" in "https://target.example.com/path/to/resource?redirected"), which can be empty, static, or request-copying. Use of \ is not permitted except to escape a following \, {, or }. An empty value results in a redirection target URL with no query component. A static value must begin with a leading "?", optionally followed by other query characters. A request-copying value must exactly match "{query}", and will be replaced with the query component of the request URL (including a leading "?" if and only if the request URL includes a query component).
        /// </summary>
        public readonly string Query;

        [OutputConstructor]
        private GetHttpRedirectTargetResult(
            string host,

            string path,

            int port,

            string protocol,

            string query)
        {
            Host = host;
            Path = path;
            Port = port;
            Protocol = protocol;
            Query = query;
        }
    }
}
