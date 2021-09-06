// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Autonomous Container Database Dataguard Association resource in Oracle Cloud Infrastructure Database service.
//
// Gets an Autonomous Container Database enabled with Autonomous Data Guard associated with the specified Autonomous Container Database.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/database"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := database.GetAutonomousContainerDatabaseDataguardAssociation(ctx, &database.GetAutonomousContainerDatabaseDataguardAssociationArgs{
// 			AutonomousContainerDatabaseDataguardAssociationId: oci_database_autonomous_container_database_dataguard_association.Test_autonomous_container_database_dataguard_association.Id,
// 			AutonomousContainerDatabaseId:                     oci_database_autonomous_container_database.Test_autonomous_container_database.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetAutonomousContainerDatabaseDataguardAssociation(ctx *pulumi.Context, args *GetAutonomousContainerDatabaseDataguardAssociationArgs, opts ...pulumi.InvokeOption) (*GetAutonomousContainerDatabaseDataguardAssociationResult, error) {
	var rv GetAutonomousContainerDatabaseDataguardAssociationResult
	err := ctx.Invoke("oci:database/getAutonomousContainerDatabaseDataguardAssociation:getAutonomousContainerDatabaseDataguardAssociation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousContainerDatabaseDataguardAssociation.
type GetAutonomousContainerDatabaseDataguardAssociationArgs struct {
	// The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousContainerDatabaseDataguardAssociationId string `pulumi:"autonomousContainerDatabaseDataguardAssociationId"`
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousContainerDatabaseId string `pulumi:"autonomousContainerDatabaseId"`
}

// A collection of values returned by getAutonomousContainerDatabaseDataguardAssociation.
type GetAutonomousContainerDatabaseDataguardAssociationResult struct {
	// The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database.  Example: `9 seconds`
	ApplyLag string `pulumi:"applyLag"`
	// The rate at which redo logs are synchronized between the associated Autonomous Container Databases.  Example: `180 Mb per second`
	ApplyRate                                         string `pulumi:"applyRate"`
	AutonomousContainerDatabaseDataguardAssociationId string `pulumi:"autonomousContainerDatabaseDataguardAssociationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Container Database that has a relationship with the peer Autonomous Container Database.
	AutonomousContainerDatabaseId string `pulumi:"autonomousContainerDatabaseId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Additional information about the current lifecycleState, if available.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The OCID of the peer Autonomous Container Database-Autonomous Data Guard association.
	PeerAutonomousContainerDatabaseDataguardAssociationId string `pulumi:"peerAutonomousContainerDatabaseDataguardAssociationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Container Database.
	PeerAutonomousContainerDatabaseId string `pulumi:"peerAutonomousContainerDatabaseId"`
	// The current state of Autonomous Data Guard.
	PeerLifecycleState string `pulumi:"peerLifecycleState"`
	// The Data Guard role of the Autonomous Container Database, if Autonomous Data Guard is enabled.
	PeerRole string `pulumi:"peerRole"`
	// The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
	ProtectionMode string `pulumi:"protectionMode"`
	// The Data Guard role of the Autonomous Container Database, if Autonomous Data Guard is enabled.
	Role string `pulumi:"role"`
	// The current state of Autonomous Data Guard.
	State string `pulumi:"state"`
	// The date and time the Autonomous DataGuard association was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time when the last role change action happened.
	TimeLastRoleChanged string `pulumi:"timeLastRoleChanged"`
	// The date and time of the last update to the apply lag, apply rate, and transport lag values.
	TimeLastSynced string `pulumi:"timeLastSynced"`
	// The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
	TransportLag string `pulumi:"transportLag"`
}
