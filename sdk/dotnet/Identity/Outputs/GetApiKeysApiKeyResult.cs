// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetApiKeysApiKeyResult
    {
        /// <summary>
        /// The key's fingerprint (e.g., 12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef).
        /// </summary>
        public readonly string Fingerprint;
        /// <summary>
        /// An Oracle-assigned identifier for the key, in this format: TENANCY_OCID/USER_OCID/KEY_FINGERPRINT.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        public readonly string InactiveStatus;
        /// <summary>
        /// The key's value.
        /// </summary>
        public readonly string KeyValue;
        /// <summary>
        /// The API key's current state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Date and time the `ApiKey` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The OCID of the user.
        /// </summary>
        public readonly string UserId;

        [OutputConstructor]
        private GetApiKeysApiKeyResult(
            string fingerprint,

            string id,

            string inactiveStatus,

            string keyValue,

            string state,

            string timeCreated,

            string userId)
        {
            Fingerprint = fingerprint;
            Id = id;
            InactiveStatus = inactiveStatus;
            KeyValue = keyValue;
            State = state;
            TimeCreated = timeCreated;
            UserId = userId;
        }
    }
}
