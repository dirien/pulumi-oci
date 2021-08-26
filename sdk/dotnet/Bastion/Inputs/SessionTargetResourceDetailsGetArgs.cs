// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Bastion.Inputs
{

    public sealed class SessionTargetResourceDetailsGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The session type.
        /// </summary>
        [Input("sessionType", required: true)]
        public Input<string> SessionType { get; set; } = null!;

        /// <summary>
        /// The display name of the target Compute instance that the session connects to.
        /// </summary>
        [Input("targetResourceDisplayName")]
        public Input<string>? TargetResourceDisplayName { get; set; }

        /// <summary>
        /// The unique identifier (OCID) of the target resource (a Compute instance, for example) that the session connects to.
        /// </summary>
        [Input("targetResourceId", required: true)]
        public Input<string> TargetResourceId { get; set; } = null!;

        /// <summary>
        /// The name of the user on the target resource operating system that the session uses for the connection.
        /// </summary>
        [Input("targetResourceOperatingSystemUserName")]
        public Input<string>? TargetResourceOperatingSystemUserName { get; set; }

        /// <summary>
        /// The port number to connect to on the target resource.
        /// </summary>
        [Input("targetResourcePort")]
        public Input<int>? TargetResourcePort { get; set; }

        /// <summary>
        /// The private IP address of the target resource that the session connects to.
        /// </summary>
        [Input("targetResourcePrivateIpAddress")]
        public Input<string>? TargetResourcePrivateIpAddress { get; set; }

        public SessionTargetResourceDetailsGetArgs()
        {
        }
    }
}
