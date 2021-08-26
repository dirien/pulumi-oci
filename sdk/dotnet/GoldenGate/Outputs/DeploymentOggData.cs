// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Outputs
{

    [OutputType]
    public sealed class DeploymentOggData
    {
        /// <summary>
        /// (Updatable) The password associated with the GoldenGate deployment console username. The password must be 8 to 30 characters long and must contain at least 1 uppercase, 1 lowercase, 1 numeric, and 1 special character. Special characters such as ‘$’, ‘^’, or ‘?’ are not allowed.
        /// </summary>
        public readonly string AdminPassword;
        /// <summary>
        /// (Updatable) The GoldenGate deployment console username.
        /// </summary>
        public readonly string AdminUsername;
        /// <summary>
        /// (Updatable) A PEM-encoded SSL certificate.
        /// </summary>
        public readonly string? Certificate;
        /// <summary>
        /// The name given to the GoldenGate service deployment. The name must be 1 to 32 characters long, must contain only alphanumeric characters and must start with a letter.
        /// </summary>
        public readonly string DeploymentName;
        /// <summary>
        /// (Updatable) A PEM-encoded private key.
        /// </summary>
        public readonly string? Key;

        [OutputConstructor]
        private DeploymentOggData(
            string adminPassword,

            string adminUsername,

            string? certificate,

            string deploymentName,

            string? key)
        {
            AdminPassword = adminPassword;
            AdminUsername = adminUsername;
            Certificate = certificate;
            DeploymentName = deploymentName;
            Key = key;
        }
    }
}
