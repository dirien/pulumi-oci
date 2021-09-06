// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Inputs
{

    public sealed class PathRouteSetPathRouteGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the target backend set for requests where the incoming URI matches the specified path.  Example: `example_backend_set`
        /// </summary>
        [Input("backendSetName", required: true)]
        public Input<string> BackendSetName { get; set; } = null!;

        /// <summary>
        /// (Updatable) The path string to match against the incoming URI path.
        /// *  Path strings are case-insensitive.
        /// *  Asterisk (*) wildcards are not supported.
        /// *  Regular expressions are not supported.
        /// </summary>
        [Input("path", required: true)]
        public Input<string> Path { get; set; } = null!;

        /// <summary>
        /// (Updatable) The type of matching to apply to incoming URIs.
        /// </summary>
        [Input("pathMatchType", required: true)]
        public Input<Inputs.PathRouteSetPathRoutePathMatchTypeGetArgs> PathMatchType { get; set; } = null!;

        public PathRouteSetPathRouteGetArgs()
        {
        }
    }
}
