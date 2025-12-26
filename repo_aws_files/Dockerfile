FROM umihico/aws-lambda-selenium-python:latest

# Install system dependencies: procps provides pkill for process cleanup
# Try microdnf first (newer Lambda images), fallback to yum (older images)
RUN (microdnf install -y procps-ng && microdnf clean all) || \
    (yum install -y procps && yum clean all) || \
    echo "Could not install procps - pkill will not be available"

# Copy the Lambda handler
COPY main.py ${LAMBDA_TASK_ROOT}/

# Install required Python dependencies
# Note: The base image already has selenium and Chrome installed
# blinker is required by selenium-wire
RUN pip install --no-cache-dir \
    boto3 \
    paramiko \
    pyotp \
    blinker==1.7.0 \
    selenium-stealth==1.0.6 \
    selenium-wire==5.1.0

# Set environment variables to disable SeleniumManager at container level
ENV SE_SELENIUM_MANAGER=false
ENV SELENIUM_MANAGER=false
ENV SELENIUM_DISABLE_DRIVER_MANAGER=1

# Set the Lambda handler entrypoint
CMD ["main.handler"]