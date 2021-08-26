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
    public sealed class HeatWaveClusterClusterNode
    {
        /// <summary>
        /// The ID of the node within MySQL HeatWave cluster.
        /// </summary>
        public readonly string? NodeId;
        /// <summary>
        /// (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        /// </summary>
        public readonly string? TimeCreated;
        /// <summary>
        /// The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        /// </summary>
        public readonly string? TimeUpdated;

        [OutputConstructor]
        private HeatWaveClusterClusterNode(
            string? nodeId,

            string? state,

            string? timeCreated,

            string? timeUpdated)
        {
            NodeId = nodeId;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
