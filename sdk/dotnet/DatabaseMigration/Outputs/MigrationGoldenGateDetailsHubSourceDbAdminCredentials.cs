// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class MigrationGoldenGateDetailsHubSourceDbAdminCredentials
    {
        /// <summary>
        /// (Updatable) Admin password
        /// </summary>
        public readonly string Password;
        /// <summary>
        /// (Updatable) Admin username
        /// </summary>
        public readonly string Username;

        [OutputConstructor]
        private MigrationGoldenGateDetailsHubSourceDbAdminCredentials(
            string password,

            string username)
        {
            Password = password;
            Username = username;
        }
    }
}
