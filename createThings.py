import boto3
import json
import time

session = boto3.Session(profile_name="YOURPROFILE", region_name="us-east-1")
iot_client = session.client("iot", "us-east-1")


def create_thing(thing_name):
    """Creates an IoT thing."""
    try:
        response = iot_client.create_thing(thingName=thing_name)
        print(f"Thing {thing_name} created successfully.")
        return response["thingName"], response["thingArn"]
    except Exception as e:
        print(f"Error creating thing {thing_name}: {e}")
        return None, None


def create_keys_and_certificate():
    """Creates a key pair and certificate for the thing."""
    try:
        response = iot_client.create_keys_and_certificate(setAsActive=True)
        certificate_arn = response["certificateArn"]
        certificate_pem = response["certificatePem"]
        private_key = response["keyPair"]["PrivateKey"]

        return certificate_arn, certificate_pem, private_key
    except Exception as e:
        print(f"Error creating keys and certificate: {e}")
        return None, None, None


def attach_thing_principal(thing_name, certificate_arn):
    """Attaches the certificate to the thing."""
    try:
        iot_client.attach_thing_principal(
            thingName=thing_name, principal=certificate_arn
        )
        print(f"Certificate attached to {thing_name}.")
    except Exception as e:
        print(f"Error attaching certificate to {thing_name}: {e}")


def add_thing_to_thing_group(thing_name, thing_group_name):
    """Adds the thing to a thing group."""
    try:
        iot_client.add_thing_to_thing_group(
            thingGroupName=thing_group_name, thingName=thing_name
        )
        print(f"Thing {thing_name} added to group {thing_group_name}.")
    except Exception as e:
        print(f"Error adding {thing_name} to {thing_group_name}: {e}")


def create_and_attach_policy(thing_name, thing_arn):
    """Creates and attaches an IoT policy."""
    try:
        # Create policy
        policy_name = f"{thing_name}-policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iot:Publish",
                        "iot:Subscribe",
                        "iot:Connect",
                        "iot:Receive",
                    ],
                    "Resource": ["*"],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "iot:GetThingShadow",
                        "iot:UpdateThingShadow",
                        "iot:DeleteThingShadow",
                    ],
                    "Resource": ["*"],
                },
                {"Effect": "Allow", "Action": ["greengrass:*"], "Resource": ["*"]},
            ],
        }
        response = iot_client.create_policy(
            policyName=policy_name, policyDocument=json.dumps(policy_document)
        )
        # Attach  policy to the Thing
        time.sleep(5)  # Add delay to ensure Thing exists
        iot_client.attach_policy(policyName=policy_name, target=thing_arn)
        print(f"Policy {policy_name} created and attached to {thing_name}")

    except Exception as e:
        print(f"Error creating or attaching policy: {e}")


num_things = 5
thing_prefix = "MyIotThing-"
thing_group_name = "MyThingGroup"

# Create things
for i in range(num_things):
    thing_name = f"{thing_prefix}{i}"
    thing_name, thing_arn = create_thing(thing_name)
    thing_arn = thing_arn.split(":")[-1]
    time.sleep(5)
    if not thing_name or not thing_arn:
        print("creation failed")
        continue

    # Create Keys and Certificate
    certificate_arn, certificate_pem, private_key = create_keys_and_certificate()
    if not certificate_arn:
        print("cert failed")
    time.sleep(5)
    # Create and Attach Policy
    create_and_attach_policy(thing_name, thing_arn)

    #  Attach Thing Principal (Certificate)
    attach_thing_principal(thing_name, certificate_arn)

    #  Add to Thing Group
    add_thing_to_thing_group(thing_name, thing_group_name)

    # Save certificates and private keys
    with open(f"{thing_name}.cert.pem", "w") as cert_file:
        cert_file.write(certificate_pem)
    with open(f"{thing_name}.private.key", "w") as key_file:
        key_file.write(private_key)
