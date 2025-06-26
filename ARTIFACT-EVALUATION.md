# Artifact Appendix

Paper title: **Message Authentication Code with Fast Verification over Encrypted Data and Applications**

Artifacts HotCRP Id: **40**

Requested Badge: **Functional**

## Description
The artifact is a Git repository containing the main codebase and encryption configuration associated with the paper. It provides the implementation of the three entities discussed in the paper: Data Producer, Data Keeper and Data Consumer. 

### Security/Privacy Issues and Ethical Concerns (All badges)
The artifact holds no known security or privacy risks, nor does it present any ethical concerns. It does not require any special security settings to be disabled, and it does not contain any malware, sensitive data, or potentially harmful content.

## Basic Requirements (Only for Functional and Reproduced badges) 
- An AWS account.

- An S3 bucket in the account with read/write permissions. Preferably the bucket should be named secret-share-bucket and should be located in the eu-central-1 region.

- 3 AWS EC2 instances in the same subnet with docker installed on each one of them. Note that it is also possible to run all 3 entities on a single instance in separate terminal windows.

The recommended instance type in AWS is: m5.2xlarge
The minimum requirement instance type is: t2.medium

- 10GB of disk space is required on each one of the instances.

### Hardware Requirements 
See Basic Requirements section for details.

### Software Requirements 
Ubuntu 22.04 (or above) and docker are required for setting up the application.


### Estimated Time and Storage Consumption
Building the docker image can take up to 1.5hrs. Transferring it to the other machines can take up to 15 mins.

The artifact contains 2 main experiments, each corresponding to different encryption parameters provided in the Git repository. Each experiment takes approximately 2 minutes to set up and run.

The total time estimation to complete the entire setup and run procedure is ~2hrs.

Storage consumption is approximately 10GB per instance.


## Environment  
Our artifacts are accessible under the git repo: https://github.com/ASEC-lab/auth-HE-retrieval

Clone the git repo and follow the instructions in the README.md file for the setup.


### Accessibility (All badges)
The artifact is publicly accessible via the main branch in the git repository: https://github.com/ASEC-lab/auth-HE-retrieval

### Set up the environment (Only for Functional and Reproduced badges) 
See the README.md file in the repository for specific setup instructions.


### Testing the Environment (Only for Functional and Reproduced badges)
After running the docker the current path will be the Release folder. 
Type the following commands to run a basic MAC test:

```bash
make Test_Protocol
./Test_Protocol -i 16384 -e ../tests_enc_params/params_15bp_16k_batched
```
You should see a "Done" message printed at the end of the test. This indicates that the test passed successfully.

## Artifact Evaluation (Only for Functional and Reproduced badges)
Run the unbatched and batched commands for each entity as described in the README.md file

Our system has been tested on input sizes of 16384, 98304, 507904 and 2031616 in both batched and unbatched mode.

The test_enc_params folder contains encryption parameter setup for batched and unbatched modes with 16k and 32k poly modulus degree.

Please make sure to use the parameter files marked as _batched and _unbatched according to the experiment type (batched or unbatched accordingly).

### Main Results and Claims

#### Main Result 1: 
Successfully launch and run the system described in section 5 (Empirical Evaluation) of our paper.


### Experiments 

#### Experiment 1: Run the *unbatched* flow for 2031616 data points using 32k poly modulus degree
In this experiment, the data producer will generate 2031616 data points, create the secret share and unbatched MAC values and upload them to the AWS bucket.
The data consumer will then retrieve the HE encrypted secret share and MAC values from the data keeper.

To run the experiment:
Run the docker on all instances. 

On the data producer instance type:
```bash
./Data_Owner -i 2031616 --enc_param_file ../tests_enc_params/params_18bp_32k_unbatched
```
A successful run of the data producer should print messages stating that objects have been added to the bucket. Once completed, it should print "Done".

Once the data producer instance has completed running, on the data keeper instance type:
```bash
./Auxiliary_Server -i 2031616 --enc_param_file ../tests_enc_params/params_18bp_32k_unbatched
```
Once loaded, the data keeper should print a message stating that the server is listening on port 8080.

Once the data keeper instance has loaded, on the data consumer instance type:
```bash
./Destination_Server -i 2031616 --ip 127.0.0.1 --enc_param_file ../tests_enc_params/params_18bp_32k_unbatched
```
Replace 127.0.0.1 with the IP of the data keeper instance.

A successful run should print confirmation that the Secret share and MAC checks passed successfully.
Also, you will find the time measurements in /tmp/out folder of each entity. Time units are microseconds.

#### Experiment 2: Run the *batched* flow for 2031616 data points using 32k poly modulus degree
In this experiment, the data producer will generate 2031616 data points, create the secret share and batched MAC values and upload them to the AWS bucket.
The data consumer will then retrieve the HE encrypted secret share and MAC values from the data keeper.

To run the experiment:
Run the docker on all instances. 

On the data producer instance type:
```bash
./Data_Owner -i 2031616 --enc_param_file ../tests_enc_params/params_12bp_32k_batched --batched
```
A successful run of the data producer should print messages stating that objects have been added to the bucket. Once completed, it should print "Done".

Once the data producer instance has completed running, on the data keeper instance type:
```bash
./Auxiliary_Server -i 2031616 --enc_param_file ../tests_enc_params/params_12bp_32k_batched --batched
```
Once loaded, the data keeper should print a message stating that the server is listening on port 8080.

Once the data keeper instance has loaded, on the data consumer instance type:
```bash
./Destination_Server -i 2031616 --ip 127.0.0.1 --enc_param_file ../tests_enc_params/params_12bp_32k_batched --batched
```
Replace 127.0.0.1 with the IP of the data keeper instance.

A successful run of the data consumer should print confirmation that the Secret share and MAC checks passed successfully.
Also, you will find the time measurements in /tmp/out folder of each entity. Time units are microseconds.

## Limitations (Only for Functional and Reproduced badges) 
The provided software covers the SEAL based implementation and functionality of the 3 entities, as described in section 5 of the article. 
As we are applying for the Functional badge, we do not guarantee exact timing result reproduction.


## Notes on Reusability (Only for Functional and Reproduced badges)
Researches may use the code in this repository as a reference for the implementation and usage of our MAC and protocol.
