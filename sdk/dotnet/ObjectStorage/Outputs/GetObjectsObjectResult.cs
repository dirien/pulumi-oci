// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ObjectStorage.Outputs
{

    [OutputType]
    public sealed class GetObjectsObjectResult
    {
        public readonly string ArchivalState;
        /// <summary>
        /// The current entity tag (ETag) for the object.
        /// </summary>
        public readonly string Etag;
        /// <summary>
        /// Base64-encoded MD5 hash of the object data.
        /// </summary>
        public readonly string Md5;
        /// <summary>
        /// The name of the object.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Size of the object in bytes.
        /// </summary>
        public readonly string Size;
        /// <summary>
        /// The storage tier that the object is stored in.
        /// * `archival-state` - Archival state of an object. This field is set only for objects in Archive tier.
        /// </summary>
        public readonly string StorageTier;
        /// <summary>
        /// The date and time the object was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the object was modified, as described in [RFC 2616](https://tools.ietf.org/rfc/rfc2616#section-14.29).
        /// </summary>
        public readonly string TimeModified;

        [OutputConstructor]
        private GetObjectsObjectResult(
            string archivalState,

            string etag,

            string md5,

            string name,

            string size,

            string storageTier,

            string timeCreated,

            string timeModified)
        {
            ArchivalState = archivalState;
            Etag = etag;
            Md5 = md5;
            Name = name;
            Size = size;
            StorageTier = storageTier;
            TimeCreated = timeCreated;
            TimeModified = timeModified;
        }
    }
}
