// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Outputs
{

    [OutputType]
    public sealed class ChannelTarget
    {
        /// <summary>
        /// (Updatable) The username for the replication applier of the target MySQL DB System.
        /// </summary>
        public readonly string? ApplierUsername;
        /// <summary>
        /// (Updatable) The case-insensitive name that identifies the replication channel. Channel names must follow the rules defined for [MySQL identifiers](https://dev.mysql.com/doc/refman/8.0/en/identifiers.html). The names of non-Deleted Channels must be unique for each DB System.
        /// </summary>
        public readonly string? ChannelName;
        /// <summary>
        /// The OCID of the target DB System.
        /// </summary>
        public readonly string DbSystemId;
        /// <summary>
        /// (Updatable) The specific target identifier.
        /// </summary>
        public readonly string TargetType;

        [OutputConstructor]
        private ChannelTarget(
            string? applierUsername,

            string? channelName,

            string dbSystemId,

            string targetType)
        {
            ApplierUsername = applierUsername;
            ChannelName = channelName;
            DbSystemId = dbSystemId;
            TargetType = targetType;
        }
    }
}
