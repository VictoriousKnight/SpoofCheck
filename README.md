# SpoofCheck

Python Script to check if your domain is Vulnerable to Spoofing or not.

Before running the script, make sure you have installed the "dnspython" package.

To install dnspyhton on your system:
`pip install dnspython` 

# How to run:
To run against one domain:
`python3 SpoofCheck.py -d yourdomain.com `

To run against multiple domains stored in a file:
`python3 SpoofCheck.py -f domainfile.txt`

Null string will be detected and ignored

Note that the path provided for the file must be a valid one
