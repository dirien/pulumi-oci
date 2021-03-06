// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlDbSystemChannelTargetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The username for the replication applier of the target MySQL DB System.
        /// </summary>
        [Input("applierUsername")]
        public Input<string>? ApplierUsername { get; set; }

        /// <summary>
        /// The case-insensitive name that identifies the replication channel. Channel names must follow the rules defined for [MySQL identifiers](https://dev.mysql.com/doc/refman/8.0/en/identifiers.html). The names of non-Deleted Channels must be unique for each DB System.
        /// </summary>
        [Input("channelName")]
        public Input<string>? ChannelName { get; set; }

        /// <summary>
        /// The OCID of the source DB System.
        /// </summary>
        [Input("dbSystemId")]
        public Input<string>? DbSystemId { get; set; }

        /// <summary>
        /// The specific target identifier.
        /// </summary>
        [Input("targetType")]
        public Input<string>? TargetType { get; set; }

        public MysqlDbSystemChannelTargetArgs()
        {
        }
    }
}
