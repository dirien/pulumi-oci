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
    public sealed class GetConnectionSshDetailsResult
    {
        /// <summary>
        /// Name of the host the sshkey is valid for.
        /// </summary>
        public readonly string Host;
        public readonly string Sshkey;
        /// <summary>
        /// Sudo location
        /// </summary>
        public readonly string SudoLocation;
        /// <summary>
        /// SSH user
        /// </summary>
        public readonly string User;

        [OutputConstructor]
        private GetConnectionSshDetailsResult(
            string host,

            string sshkey,

            string sudoLocation,

            string user)
        {
            Host = host;
            Sshkey = sshkey;
            SudoLocation = sudoLocation;
            User = user;
        }
    }
}
