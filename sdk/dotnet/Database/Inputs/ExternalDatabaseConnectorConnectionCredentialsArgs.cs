// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class ExternalDatabaseConnectorConnectionCredentialsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the credential information that used to connect to the database. The name should be in "x.y" format, where the length of "x" has a maximum of 64 characters, and length of "y" has a maximum of 199 characters. The name strings can contain letters, numbers and the underscore character only. Other characters are not valid, except for the "." character that separates the "x" and "y" portions of the name. *IMPORTANT* - The name must be unique within the Oracle Cloud Infrastructure region the credential is being created in. If you specify a name that duplicates the name of another credential within the same Oracle Cloud Infrastructure region, you may overwrite or corrupt the credential that is already using the name.
        /// </summary>
        [Input("credentialName")]
        public Input<string>? CredentialName { get; set; }

        /// <summary>
        /// (Updatable) The type of credential used to connect to the database.
        /// </summary>
        [Input("credentialType")]
        public Input<string>? CredentialType { get; set; }

        /// <summary>
        /// (Updatable) The password that will be used to connect to the database.
        /// </summary>
        [Input("password")]
        public Input<string>? Password { get; set; }

        /// <summary>
        /// (Updatable) The role of the user that will be connecting to the database.
        /// </summary>
        [Input("role")]
        public Input<string>? Role { get; set; }

        /// <summary>
        /// (Updatable) The username that will be used to connect to the database.
        /// </summary>
        [Input("username")]
        public Input<string>? Username { get; set; }

        public ExternalDatabaseConnectorConnectionCredentialsArgs()
        {
        }
    }
}
