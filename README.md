# Message Authentication Code with Fast Verification over Encrypted Data and Applications

The software in this reporistory is licensed under the MIT license. See the LICENSE file for full details.

# Prerequisites:

- Access to an AWS account
- An S3 bucket in the account, read/write permissions to the bucket. The assumption is that the bucket will be named secret-share-bucket and that it will be located in the region: eu-central-1. If you are using an AWS bucket with a different name or region, update accordingly in Servers\_Protocol.h.
- Launch 3 EC2 instances in the same subnet (or any other type of virtual machines with IP connectivity) with Docker installed on each one of them. Each instance will represent an entity: Data Producer, Data Keeper and Data Consumer.
- Open port 8080 for TCP access on the Data Keeper machine.
- It is also possible to run all 3 entities on a single machine in separate terminal windows.

# Building the Docker image:

- If you are using an AWS bucket with a different name or region, update accordingly in Servers\_Protocol.h.

- Build the image using the provided Dockerfile on each of the machines. Alternatively it is possible to build on one machine, save the image to a file, copy to the other machines and load from there. 

# Running the containers:

- Run the container using the command: 
```PowerShell
docker run -it \<dockername\>
```
- After running the container on each machine, add your aws credentials for accessing the S3 bucket (access key and secret key) to ~/.aws/credentials

## On Data Producer instance:

- Type ```./Data_Owner -h``` to see all options for running the data producer instance.

Recommended commands:
- For generating 98304 data points in unbatched mode run:
```PowerShell
./Data_Owner -i 98304 --enc_param_file ../tests_enc_params/params_18bp_32k_unbatched 
```
- For generating 98304 data points in the batched mode run:
```PowerShell
./Data_Owner -i 98304 --enc_param_file ../tests_enc_params/params_12bp_32k_batched --batched
```

- Wait for the command to complete successfully.

## On the Data Keeper instance:

- Type ```./Auxiliary_Server -h``` to see all options for running the data keeper instance.

Recommended commands:
- For launching the server to transfer 98304 data points in unbatched mode run:
```PowerShell
./Auxiliary_Server -i 98304 --enc_param_file ../tests_enc_params/params_18bp_32k_unbatcehd
```
- For launching the server to transfer 98304 data points in batched mode run:
```PowerShell
./Data_Owner -i 98304 --enc_param_file ../tests_enc_params/params_12bp_32k_batched --batched
```
- You will see that the server is listening on port 8080

## On the Data consumer instance:


- Type ```./Destination_Server -h``` to see all options for running the data consumer instance.

Recommended commands:
- For consuming 98304 data points in unbatched mode run:
```PowerShell
./Destination_Server -i 98304 --ip 127.0.0.1 --enc_param_file ../tests_enc_params/params_18bp_32k_unbatcehd
```
- For consuming 98304 data points in batched mode run:
```PowerShell
./Destination_Server -i 98304 --ip 127.0.0.1 --enc_param_file ../tests_enc_params/params_12bp_32k_batched --batched
```
In the above commands replace 127.0.0.1 with the IP of the Data Keeper instance. 

When the transfer completes you should see prints confirming that the Secret share and MAC checks passed successfully.

## Time Measurements
The time measurements in csv format can be found under the /tmp/out folder on each instance. The time measurements values are in microseconds.
