// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class GetDeploymentSpecificationRouteRequestPoliciesBodyValidationContentResult
    {
        /// <summary>
        /// The media type is a [media type range](https://tools.ietf.org/html/rfc7231#appendix-D) subset restricted to the following schema
        /// </summary>
        public readonly string MediaType;
        /// <summary>
        /// Validation type defines the content validation method.
        /// </summary>
        public readonly string ValidationType;

        [OutputConstructor]
        private GetDeploymentSpecificationRouteRequestPoliciesBodyValidationContentResult(
            string mediaType,

            string validationType)
        {
            MediaType = mediaType;
            ValidationType = validationType;
        }
    }
}
