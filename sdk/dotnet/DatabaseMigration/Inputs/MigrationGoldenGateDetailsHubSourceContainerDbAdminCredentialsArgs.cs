// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class MigrationGoldenGateDetailsHubSourceContainerDbAdminCredentialsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Admin password
        /// </summary>
        [Input("password", required: true)]
        public Input<string> Password { get; set; } = null!;

        /// <summary>
        /// (Updatable) Admin username
        /// </summary>
        [Input("username", required: true)]
        public Input<string> Username { get; set; } = null!;

        public MigrationGoldenGateDetailsHubSourceContainerDbAdminCredentialsArgs()
        {
        }
    }
}
