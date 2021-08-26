// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Audit.Outputs
{

    [OutputType]
    public sealed class GetEventsAuditEventResult
    {
        /// <summary>
        /// The version of the CloudEvents specification. The structure of the envelope follows the  [CloudEvents](https://github.com/cloudevents/spec) industry standard format hosted by the [Cloud Native Computing Foundation ( CNCF)](https://www.cncf.io/).
        /// </summary>
        public readonly string CloudEventsVersion;
        /// <summary>
        /// The content type of the data contained in `data`.  Example: `application/json`
        /// </summary>
        public readonly string ContentType;
        /// <summary>
        /// The payload of the event. Information within `data` comes from the resource emitting the event.
        /// </summary>
        public readonly Outputs.GetEventsAuditEventDataResult Data;
        /// <summary>
        /// The GUID of the event.
        /// </summary>
        public readonly string EventId;
        /// <summary>
        /// The time the event occurred, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2019-09-18T00:10:59.252Z`
        /// </summary>
        public readonly string EventTime;
        /// <summary>
        /// The type of event that happened.
        /// </summary>
        public readonly string EventType;
        /// <summary>
        /// The version of the event type. This version applies to the payload of the event, not the envelope. Use `cloudEventsVersion` to determine the version of the envelope.  Example: `2.0`
        /// </summary>
        public readonly string EventTypeVersion;
        /// <summary>
        /// The source of the event.  Example: `ComputeApi`
        /// </summary>
        public readonly string Source;

        [OutputConstructor]
        private GetEventsAuditEventResult(
            string cloudEventsVersion,

            string contentType,

            Outputs.GetEventsAuditEventDataResult data,

            string eventId,

            string eventTime,

            string eventType,

            string eventTypeVersion,

            string source)
        {
            CloudEventsVersion = cloudEventsVersion;
            ContentType = contentType;
            Data = data;
            EventId = eventId;
            EventTime = eventTime;
            EventType = eventType;
            EventTypeVersion = eventTypeVersion;
            Source = source;
        }
    }
}