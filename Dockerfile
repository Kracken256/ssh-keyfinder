
# Must be 20.04 for openssh 8.2p1
FROM ubuntu:20.04


# Install dependencies
RUN apt update
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt -y install tzdata
RUN apt -y install ssh python3 python3-pip gdb

# Install pwntools
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install pwntools Flask

# Copy files
COPY . /opt/ssh-keyfinder

# Set working directory
WORKDIR /opt/ssh-keyfinder/web

EXPOSE 3000

# Run the server
CMD ["python3", "./server.py"]
