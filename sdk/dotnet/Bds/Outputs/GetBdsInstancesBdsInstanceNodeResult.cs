// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Bds.Outputs
{

    [OutputType]
    public sealed class GetBdsInstancesBdsInstanceNodeResult
    {
        /// <summary>
        /// The list of block volumes attached to a given node.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBdsInstancesBdsInstanceNodeAttachedBlockVolumeResult> AttachedBlockVolumes;
        /// <summary>
        /// The name of the availability domain in which the node is running.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The name of the fault domain in which the node is running.
        /// </summary>
        public readonly string FaultDomain;
        /// <summary>
        /// The fully-qualified hostname (FQDN) of the node.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The OCID of the image from which the node was created.
        /// </summary>
        public readonly string ImageId;
        /// <summary>
        /// The OCID of the underlying Oracle Cloud Infrastructure Compute instance.
        /// </summary>
        public readonly string InstanceId;
        /// <summary>
        /// IP address of the node.
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// Cluster node type.
        /// </summary>
        public readonly string NodeType;
        /// <summary>
        /// Shape of the node.
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// The fingerprint of the SSH key used for node access.
        /// </summary>
        public readonly string SshFingerprint;
        /// <summary>
        /// The state of the cluster.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The OCID of the subnet in which the node is to be created.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetBdsInstancesBdsInstanceNodeResult(
            ImmutableArray<Outputs.GetBdsInstancesBdsInstanceNodeAttachedBlockVolumeResult> attachedBlockVolumes,

            string availabilityDomain,

            string displayName,

            string faultDomain,

            string hostname,

            string imageId,

            string instanceId,

            string ipAddress,

            string nodeType,

            string shape,

            string sshFingerprint,

            string state,

            string subnetId,

            string timeCreated)
        {
            AttachedBlockVolumes = attachedBlockVolumes;
            AvailabilityDomain = availabilityDomain;
            DisplayName = displayName;
            FaultDomain = faultDomain;
            Hostname = hostname;
            ImageId = imageId;
            InstanceId = instanceId;
            IpAddress = ipAddress;
            NodeType = nodeType;
            Shape = shape;
            SshFingerprint = sshFingerprint;
            State = state;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
        }
    }
}
