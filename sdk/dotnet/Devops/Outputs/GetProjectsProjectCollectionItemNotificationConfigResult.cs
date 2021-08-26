// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Outputs
{

    [OutputType]
    public sealed class GetProjectsProjectCollectionItemNotificationConfigResult
    {
        /// <summary>
        /// The topic ID for notifications.
        /// </summary>
        public readonly string TopicId;

        [OutputConstructor]
        private GetProjectsProjectCollectionItemNotificationConfigResult(string topicId)
        {
            TopicId = topicId;
        }
    }
}
