// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oda
{
    public static class GetOdaInstance
    {
        /// <summary>
        /// This data source provides details about a specific Oda Instance resource in Oracle Cloud Infrastructure Digital Assistant service.
        /// 
        /// Gets the specified Digital Assistant instance.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testOdaInstance = Output.Create(Oci.Oda.GetOdaInstance.InvokeAsync(new Oci.Oda.GetOdaInstanceArgs
        ///         {
        ///             OdaInstanceId = oci_oda_oda_instance.Test_oda_instance.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetOdaInstanceResult> InvokeAsync(GetOdaInstanceArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetOdaInstanceResult>("oci:oda/getOdaInstance:getOdaInstance", args ?? new GetOdaInstanceArgs(), options.WithVersion());
    }


    public sealed class GetOdaInstanceArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique Digital Assistant instance identifier.
        /// </summary>
        [Input("odaInstanceId", required: true)]
        public string OdaInstanceId { get; set; } = null!;

        public GetOdaInstanceArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetOdaInstanceResult
    {
        /// <summary>
        /// Identifier of the compartment that the instance belongs to.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// URL for the connector's endpoint.
        /// </summary>
        public readonly string ConnectorUrl;
        /// <summary>
        /// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Description of the Digital Assistant instance.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// User-defined name for the Digital Assistant instance. Avoid entering confidential information. You can change this value.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Unique immutable identifier that was assigned when the instance was created.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current sub-state of the Digital Assistant instance.
        /// </summary>
        public readonly string LifecycleSubState;
        public readonly string OdaInstanceId;
        /// <summary>
        /// Shape or size of the instance.
        /// </summary>
        public readonly string ShapeName;
        /// <summary>
        /// The current state of the Digital Assistant instance.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// A message that describes the current state in more detail. For example, actionable information about an instance that's in the `FAILED` state.
        /// </summary>
        public readonly string StateMessage;
        /// <summary>
        /// When the Digital Assistant instance was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// When the Digital Assistance instance was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// URL for the Digital Assistant web application that's associated with the instance.
        /// </summary>
        public readonly string WebAppUrl;

        [OutputConstructor]
        private GetOdaInstanceResult(
            string compartmentId,

            string connectorUrl,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleSubState,

            string odaInstanceId,

            string shapeName,

            string state,

            string stateMessage,

            string timeCreated,

            string timeUpdated,

            string webAppUrl)
        {
            CompartmentId = compartmentId;
            ConnectorUrl = connectorUrl;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleSubState = lifecycleSubState;
            OdaInstanceId = odaInstanceId;
            ShapeName = shapeName;
            State = state;
            StateMessage = stateMessage;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            WebAppUrl = webAppUrl;
        }
    }
}
