// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Artifacts.Outputs
{

    [OutputType]
    public sealed class GetContainerRepositoryReadmeResult
    {
        /// <summary>
        /// Readme content. Avoid entering confidential information.
        /// </summary>
        public readonly string Content;
        /// <summary>
        /// Readme format. Supported formats are text/plain and text/markdown.
        /// </summary>
        public readonly string Format;

        [OutputConstructor]
        private GetContainerRepositoryReadmeResult(
            string content,

            string format)
        {
            Content = content;
            Format = format;
        }
    }
}
