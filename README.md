# 15-441/641 Project 2: TCP in the Wild

Welcome to Project 2! Please read the handout and starter code thoroughly before you begin. This README contains a quick summary to get your testing environment set up.

## Setting up Vagrant and the virtual machines
First, download and install [Vagrant](https://learn.hashicorp.com/collections/vagrant/getting-started) and [VirtualBox](https://www.virtualbox.org/) on your machine. If you're using an M1 Mac, you may need to use an EC2 instance on AWS or other cloud services providers as VirtualBox may not be fully functional.

Once you have Vagrant and VirtualBox installed, navigate inside this repo and run:

```bash
vagrant up  # builds the server and client virtual machines, which takes a while
vagrant ssh {client | server}   # connects to either the client or server using SSH
```

Vagrant keeps all files synchronized between your host machine and the two VMs. In other words, the code will update automatically on the VMs as you edit it on your computer. Similarly, debugging files and other files generated on the VMs will automatically appear on your host machine.

## Testing
At this point, you should be able to run tests on the virtual machines. On either the client or server VM, navigate to `/vagrant/15-441-project-2/` and run `make test`.

Note that the test files are _incomplete_! You are expected to build upon them and write more extensive tests (doing so will help you write better code and save you grief during debugging)!

## Files
The following files have been provided for you:

* `Vagrantfile`: Defines the structure, IP addresses, and dependencies in the virtual machines. Feel free to modify this file to add any additional testing tools as you see fit. Remember to document your changes in `tests.txt`!

* `README`: A description of your files, as well as your algorithm in CP3.

* `tests.txt`: A brief writeup describing your testing strategy, and any tools you used in the process of testing.

* `gen_graph.py`: Takes in a PCAP file and generates a graph. Feel free to modify this file to profile Reno and your algorithm in CP2 and CP3.

* `tcp.lua`: A Lua plugin that allows Wireshark to decode CMU-TCP headers. Copy the file to the directory described in <https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html> to use the plugin.

* `test_cp1.py`: Test script for CP1 that is executed with `make test`. You should add your own tests to this file.

* `test_cp2.py`: Test script for CP2 that can be executed with `make test`. You should add your own tests to this file.

* `score_calculator.py`: Score calculator for your custom congestion control algorithm in CP3. See the comments in the file and `cp3_instructions.txt` for more details on its usage.

* `cp3_instructions.txt`: Some further instructions on running `score_calculator.py` for CP3.
    
* `grading.h`: These are variables that we will use to test your implementation. We will be replacing this file when running tests, and hence you should test your implementation with different values. 

* `server.c`: An application using the server side of your transport protocol. We will test your code using a different server program, so do not keep any variables or functions here that your protocol uses. 

* `client.c`: An application using the client side of your transport protocol. We will test your code using a different client application, so do not keep any variables or functions here that your protocol uses. 

* `cmu_tcp.c`: This contains the main socket functions required of your TCP socket including reading, writing, opening and closing. 

* `backend.c`: This file contains the code used to emulate the buffering and sending of packets. This is where you should spend most of your time.

* `cmu_packet.h`: This file describes the basic packet format and header. You are not allowed to modify this file in Checkpoints 1 and 2! The scripts that we provide to help you graph your packet traces rely on this file being unchanged. All the communication between your server and client will use UDP as the underlying protocol. All packets will begin with the common header described as follows:

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
