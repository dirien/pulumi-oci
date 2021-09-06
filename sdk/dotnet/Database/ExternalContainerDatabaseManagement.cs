// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This resource provides the External Container Database Management resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Enables Database Management Service for the external container database.
    /// For more information about the Database Management Service, see
    /// [Database Management Service](https://docs.cloud.oracle.com/iaas/Content/ExternalDatabase/Concepts/databasemanagementservice.htm).
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:database/externalContainerDatabaseManagement:ExternalContainerDatabaseManagement")]
    public partial class ExternalContainerDatabaseManagement : Pulumi.CustomResource
    {
        [Output("enableManagement")]
        public Output<bool> EnableManagement { get; private set; } = null!;

        /// <summary>
        /// The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Output("externalContainerDatabaseId")]
        public Output<string> ExternalContainerDatabaseId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        /// </summary>
        [Output("externalDatabaseConnectorId")]
        public Output<string> ExternalDatabaseConnectorId { get; private set; } = null!;

        /// <summary>
        /// The Oracle license model that applies to the external database. Required only for enabling database management.
        /// </summary>
        [Output("licenseModel")]
        public Output<string> LicenseModel { get; private set; } = null!;


        /// <summary>
        /// Create a ExternalContainerDatabaseManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ExternalContainerDatabaseManagement(string name, ExternalContainerDatabaseManagementArgs args, CustomResourceOptions? options = null)
            : base("oci:database/externalContainerDatabaseManagement:ExternalContainerDatabaseManagement", name, args ?? new ExternalContainerDatabaseManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ExternalContainerDatabaseManagement(string name, Input<string> id, ExternalContainerDatabaseManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:database/externalContainerDatabaseManagement:ExternalContainerDatabaseManagement", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing ExternalContainerDatabaseManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ExternalContainerDatabaseManagement Get(string name, Input<string> id, ExternalContainerDatabaseManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new ExternalContainerDatabaseManagement(name, id, state, options);
        }
    }

    public sealed class ExternalContainerDatabaseManagementArgs : Pulumi.ResourceArgs
    {
        [Input("enableManagement", required: true)]
        public Input<bool> EnableManagement { get; set; } = null!;

        /// <summary>
        /// The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("externalContainerDatabaseId", required: true)]
        public Input<string> ExternalContainerDatabaseId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        /// </summary>
        [Input("externalDatabaseConnectorId", required: true)]
        public Input<string> ExternalDatabaseConnectorId { get; set; } = null!;

        /// <summary>
        /// The Oracle license model that applies to the external database. Required only for enabling database management.
        /// </summary>
        [Input("licenseModel")]
        public Input<string>? LicenseModel { get; set; }

        public ExternalContainerDatabaseManagementArgs()
        {
        }
    }

    public sealed class ExternalContainerDatabaseManagementState : Pulumi.ResourceArgs
    {
        [Input("enableManagement")]
        public Input<bool>? EnableManagement { get; set; }

        /// <summary>
        /// The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("externalContainerDatabaseId")]
        public Input<string>? ExternalContainerDatabaseId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        /// </summary>
        [Input("externalDatabaseConnectorId")]
        public Input<string>? ExternalDatabaseConnectorId { get; set; }

        /// <summary>
        /// The Oracle license model that applies to the external database. Required only for enabling database management.
        /// </summary>
        [Input("licenseModel")]
        public Input<string>? LicenseModel { get; set; }

        public ExternalContainerDatabaseManagementState()
        {
        }
    }
}
