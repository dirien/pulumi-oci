// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Bastion.Outputs
{

    [OutputType]
    public sealed class GetSessionsSessionResult
    {
        /// <summary>
        /// The unique identifier (OCID) of the bastion in which to list sessions.
        /// </summary>
        public readonly string BastionId;
        /// <summary>
        /// The name of the bastion that is hosting this session.
        /// </summary>
        public readonly string BastionName;
        /// <summary>
        /// The public key of the bastion host. You can use this to verify that you're connecting to the correct bastion.
        /// </summary>
        public readonly string BastionPublicHostKeyInfo;
        /// <summary>
        /// The username that the session uses to connect to the target resource.
        /// </summary>
        public readonly string BastionUserName;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The unique identifier (OCID) of the session, which can't be changed after creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Public key details for a bastion session.
        /// </summary>
        public readonly Outputs.GetSessionsSessionKeyDetailsResult KeyDetails;
        /// <summary>
        /// The type of the key used to connect to the session. PUB is a standard public key in OpenSSH format.
        /// </summary>
        public readonly string KeyType;
        /// <summary>
        /// A message describing the current session state in more detail.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The amount of time the session can remain active.
        /// </summary>
        public readonly int SessionTtlInSeconds;
        /// <summary>
        /// The connection message for the session.
        /// </summary>
        public readonly ImmutableDictionary<string, object> SshMetadata;
        /// <summary>
        /// The current state of the session.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Details about a bastion session's target resource.
        /// </summary>
        public readonly Outputs.GetSessionsSessionTargetResourceDetailsResult TargetResourceDetails;
        /// <summary>
        /// The time the session was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the session was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetSessionsSessionResult(
            string bastionId,

            string bastionName,

            string bastionPublicHostKeyInfo,

            string bastionUserName,

            string displayName,

            string id,

            Outputs.GetSessionsSessionKeyDetailsResult keyDetails,

            string keyType,

            string lifecycleDetails,

            int sessionTtlInSeconds,

            ImmutableDictionary<string, object> sshMetadata,

            string state,

            Outputs.GetSessionsSessionTargetResourceDetailsResult targetResourceDetails,

            string timeCreated,

            string timeUpdated)
        {
            BastionId = bastionId;
            BastionName = bastionName;
            BastionPublicHostKeyInfo = bastionPublicHostKeyInfo;
            BastionUserName = bastionUserName;
            DisplayName = displayName;
            Id = id;
            KeyDetails = keyDetails;
            KeyType = keyType;
            LifecycleDetails = lifecycleDetails;
            SessionTtlInSeconds = sessionTtlInSeconds;
            SshMetadata = sshMetadata;
            State = state;
            TargetResourceDetails = targetResourceDetails;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
