// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetTargetDatabasesTargetDatabaseCredentialsResult
    {
        /// <summary>
        /// The password of the database user.
        /// </summary>
        public readonly string Password;
        /// <summary>
        /// The database user name.
        /// </summary>
        public readonly string UserName;

        [OutputConstructor]
        private GetTargetDatabasesTargetDatabaseCredentialsResult(
            string password,

            string userName)
        {
            Password = password;
            UserName = userName;
        }
    }
}
