# Key establishment protocol between client and server

Consider a distributed client-server application where each client 'A' shares a long­term
secret with the server 'B'.

Assuming you are in a situation of mutual­trust, i.e. the client trusts the server and viceversa.
This project specifies, analyzes and finally implements a cryptographic protocol that meets the 
following requirements:
at the end of the execution of the protocol, the client establishes a session key between 'A' and 'B';
and always at the end of the execution of the protocol, the client 'A' believes that the server
'B' has the session key and viceversa.

The session key is generated by the server 'B'.

The implementation includes the realization of a prototype in which the server and the
client exchange of the ciphertext with the session key.

For further details about the design and the implementation of the project, please, see
the documentation in this repository.
