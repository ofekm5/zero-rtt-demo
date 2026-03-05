from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    CfnOutput,
)
from constructs import Construct


class PacketTestStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create VPC for packet testing with chain topology subnets
        self.vpc = ec2.Vpc(
            self,
            "PacketTestVPC",
            ip_addresses=ec2.IpAddresses.cidr("10.1.0.0/16"),
            max_azs=1,
            nat_gateways=0,
            subnet_configuration=[
                # Client subnet
                ec2.SubnetConfiguration(
                    name="Client",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                # Middle subnet (between ClientNIC and ServerNIC)
                ec2.SubnetConfiguration(
                    name="Middle",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                # Server subnet
                ec2.SubnetConfiguration(
                    name="Server",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
            ],
        )
