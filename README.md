# 15-441/641 Project 2: TCP in the Wild

Welcome to Project 2! Please read the handout carefully and thoroughly before you begin. This README will contain a quick summary to get your testing environment set up.

## Setting up Vagrant and the virtual machines
First, download and install [Vagrant](https://learn.hashicorp.com/collections/vagrant/getting-started) and [VirtualBox](https://www.virtualbox.org/) on your machine. If you're using an M1 Mac, you may need to use an EC2 instance on AWS or other cloud services providers as VirtualBox may not be fully functional.

Once you have Vagrant and VirtualBox installed, run in this directory:

```bash
vagrant up  # builds the server and client virtual machines
vagrant ssh {client | server}   # launches an SSH session into either the client or server
```

Vagrant keeps all files synchronized between your host machine and the two VMs. In other words, the code will update automatically on the VMs as you edit it on your computer. Similarly, debug and other files generated on the VMs will automatically appear on your host machine.

## Testing
At this point, you should be able to run tests on the virtual machines. On either the client or server VM, navigate to `/vagrant/15-441-project-2/` and run `make test`.

Note that the test files are _incomplete_! You are expected to build upon them and write more extensive tests (and it'll help you write better code, and save you grief during debugging!)

## Files
The following files have been provided for you to use:

* `Vagrantfile`: defines the structure, IP addresses, and dependencies in the virtual machines. Feel free to modify this file to add any additional testing tools as you see fit. Remember to document your changes in `tests.txt`!

* `gen_graph.py`: takes in a PCAP file and generates a graph. You should modify this file to profile Reno and your algorithm in CP3

* `test_cp1.py`: test script for CP1 that is executed with `make test`. You should add your own tests to this file

* `test_cp2.py`: test script for CP2 that can be executed with `make test`. You should add your own tests to this file

* `score_calculator.py`: score calculator for your congestion control algorithm in CP3. See the comments in the file and `cp3_instructions.txt` for more details on its usage

* `cp3_instructions.txt`: some further instructions on running `score_calculator.py` for CP3

* `cmu_packet.h`: this file describes the basic packet format and header. You are not allowed to modify this file in Checkpoints 1 and 2! The scripts that we provide to help you graph your packet traces rely on this file being unchanged.
    
* `grading.h`: these are variables that we will use to test your implementation. We will be replacing it when running tests, and hence you should test your implementation with different values. 

* `server.c`: an application using the server side of your transport protocol. We will test your code using a different server program, so do not keep any variables or functions here that are necessary for your protocol to use. 

* `client.c`: an application using the client side of your transport protocol. We will test your code using a different client application, so do not keep any variables or functions here that are necessary for your protocol to use. 

* `cmu_tcp.c`: this contains the main socket functions required of your TCP socket including reading, writing, opening and closing. 

* `backend.c`: this file contains the code used to emulate the buffering and sending of packets. This is where you should spend most of your time.

* `cmu_packet.h`: all the communication between your server and client will use UDP as the underlying protocol. All packets will begin with the common header described in `cmu_packet.h` as follows:

    * Course Number 		    [4 bytes]
    * Source Port 			    [2 bytes]
    * Destination Port 		    [2 bytes]
    * Sequence Number 		    [4 bytes]
    * Acknowledgement Number 	[4 bytes]
    * Header Length		        [2 bytes]
    * Packet Length			    [2 bytes]
    * Flags				        [1 byte]
    * Advertised Window		    [2 bytes]
    * Extension length		    [2 bytes]
    * Extension Data		    [You Decide]
