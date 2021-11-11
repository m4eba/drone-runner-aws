# AWS Runner

This runner provisions EC2 instances in AWS for both windows and Linux. It also sets up SSH access and installs git. The installation of Docker on the instances allows the running of the build in Hybrid mode: where Drone Plugins can run or build steps in container along with build steps on the instance operating system. Pools of hot swappable EC2 instances are created on startup of the runner to improve build spin up time.

## Installation

For more information about installing this runner look at the [installation documentation](https://docs.drone.io/runner/aws/overview/).

## Configuration

For more information about configuring this runner look at the [configuration documentation](https://docs.drone.io/runner/aws/configuration/).

## Creating a build pipelines

For more information about creating a build pipeline look at the [pipeline documentation](https://docs.drone.io/pipeline/aws/overview/).

## Design

This runner was initially designed in the following [proposal](https://github.com/drone/proposal/blob/master/design/01-aws-runner.md).

## Future Improvements

+ tmate integration
+ cli sub command to print ec2 instances information
+ cli sub command to terminate all runner ec2 instances

## developer setup for testing / using the lite engine

+ build the lite-engine
+ host the lite-engine binary `python3 -m http.server`
+ run ngrok to expose the webserver `ngrok http 8000`
+ add the ngrok url to the env file `DRONE_SETTINGS_LITE_ENGINE_PATH=https://c6bf-80-7-0-64.ngrok.io`
+ make sure to add port 9079 to your incoming network aws security group.
