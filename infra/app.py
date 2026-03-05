#!/usr/bin/env python3
import os
import aws_cdk as cdk
from cdk.smartnics_stack import SmartNicsStack
from cdk.packet_test_stack import PacketTestStack


app = cdk.App()

packet_test_stack = PacketTestStack(
    app,
    "PacketTestStack",
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region="eu-central-1",  # Frankfurt
    ),
)

SmartNicsStack(
    app,
    "SmartNicsStack",
    vpc=packet_test_stack.vpc,
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region="eu-central-1",  # Frankfurt
    ),
)

app.synth()
