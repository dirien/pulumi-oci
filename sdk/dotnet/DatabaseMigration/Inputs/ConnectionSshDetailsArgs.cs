// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class ConnectionSshDetailsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Name of the host the sshkey is valid for.
        /// </summary>
        [Input("host", required: true)]
        public Input<string> Host { get; set; } = null!;

        /// <summary>
        /// (Updatable) Private ssh key string.
        /// </summary>
        [Input("sshkey", required: true)]
        public Input<string> Sshkey { get; set; } = null!;

        /// <summary>
        /// (Updatable) Sudo location
        /// </summary>
        [Input("sudoLocation")]
        public Input<string>? SudoLocation { get; set; }

        /// <summary>
        /// (Updatable) SSH user
        /// </summary>
        [Input("user", required: true)]
        public Input<string> User { get; set; } = null!;

        public ConnectionSshDetailsArgs()
        {
        }
    }
}
