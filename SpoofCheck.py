import sys
import subprocess
import argparse
import dns.resolver
import re

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def help():
    print("Accepted parameters:\n")
    print("Use -d along with a domain name, example python SpoofCheck.py -d domain.com")
    print("Null string will be detected and ignored\n")
    print(
        "Use -f along with a file containing domain names, example python SpoofCheck.py -f domains.txt"
    )
    print("Note that the path provided for the file must be a valid one\n")


def check_url(domain):
    retval = 0

    # Check SPF record
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt_string = rdata.strings[0].decode("utf-8")
            if txt_string.startswith("v=spf1"):
                print(f"\n{GREEN}SPF Record found{NC} for {domain}: {txt_string}")
                break
    except dns.resolver.NoAnswer:
        print(f"{RED}No SPF record found{NC} for", domain)
    except dns.resolver.NXDOMAIN:
        print(f"{RED}No SPF record found{NC} for", domain)

    # Check DKIM record
    try:
        selector = "default"
        command = ["dig", f"{selector}._domainkey.{domain}", "TXT"]
        cmd_output = subprocess.run(
            command, capture_output=True, text=True
        ).stdout.splitlines()

        output = None

        for line in cmd_output:
            match = re.search(r"opcode: (\w+), status: (\w+), id: (\d+)$", line)
            if match:
                output = match.group(0)
                if "NOERROR" in output:
                    print(f"\n{GREEN}DKIM Record found{NC} for {domain}: {output}")
                elif "NXDOMAIN" in output:
                    print(f"\n{RED}No DKIM Record found{NC} for {domain}: {output}")
                else:
                    print(f"\n{RED}No DKIM Record found{NC} for {domain}")
                break
        else:
            print(f"\n{RED}No DKIM Record found{NC} for {domain}")

    except dns.resolver.NoAnswer:
        print(f"\n{RED}No DKIM record found{NC} for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"\n{RED}No DKIM record found{NC} for {domain}")
    except dns.resolver.NoNameservers:
        print(f"\n{RED}No nameservers found{NC} for the domain {domain}")
    except dns.resolver.NoRootSOA:
        print(f"\n{RED}No root SOA record found{NC} for the domain {domain}")

    # Check DMARK records

    try:

        command = ["nslookup", "-type=txt", f"_dmarc.{domain}"]
        cmd_output = subprocess.run(
            command, capture_output=True, text=True
        ).stdout.splitlines()

        output = None

        for line in cmd_output:
            match = re.search(r'_dmarc\..+?(\ttext\s*=\s*".+?")', line)
            if match:
                output = match.group(1)
                print(f"\n{GREEN}DMARC Record found{NC} for {domain}: {output}")
                break

        if output is not None:
            if "p=reject" in output:
                print(f"\n{domain} is {GREEN}NOT vulnerable{NC}")
            elif "p=quarantine" in output:
                print(
                    f"\n{domain} {YELLOW}can be vulnerable{NC} (email will be sent to spam)"
                )
            elif "p=none" in output:
                print(f"\n{domain} is {RED}vulnerable{NC}")
                retval = 1
            else:
                print(f"\n{domain} is {RED}vulnerable{NC} (No DMARC record found)")
                retval = 1
        else:
            print(f"\nNo DMARC record found for {domain}")
            print(f"\n{domain} is {RED}vulnerable{NC} (No DMARC record found)")
            retval = 1
    except subprocess.CalledProcessError:
        print(f"\nError: Could not retrieve DMARC record for {domain}")
        retval = 1

    # Check ARC record
    try:
        command = ["dig", f"_authres.{domain}", "TXT"]
        cmd_output = subprocess.run(
            command, capture_output=True, text=True
        ).stdout.splitlines()

        output = None

        for line in cmd_output:
            match = re.search(r'IN\s+TXT\s+"(.+?)"', line)
            if match:
                output = match.group(1)
                print("TXT Record found:", output)

                if "v=arc1" in output:
                    print(f"\name(){domain} is {GREEN}ARC-enabled{NC}.")
                    break

        else:
            print(f"\n{domain} is {RED}not ARC-enabled{NC}.")

    except subprocess.CalledProcessError:
        print(f"\nError: Could not retrieve ARC record for {domain}")

    return retval


def check_file(input_file):
    with open(input_file, "r") as file:
        lines = file.readlines()
    counter = 0
    vulnerables = 0
    for line in lines:
        counter += 1
        domain = line.strip()
        vulnerables += check_url(domain)
        if domain in vulnerables:
            print(f"\n{domain} is {RED}vulnerable{NC}")
    print(f"\n{vulnerables} out of {counter} domains are {RED}vulnerable{NC}")


def main():
    parser = argparse.ArgumentParser(
        description="Check if domains are vulnerable to email spoofing."
    )
    parser.add_argument("-d", "--domain", help="Single domain name to check")
    parser.add_argument("-f", "--file", help="File containing domain names to check")
    args = parser.parse_args()

    if args.domain:
        check_url(args.domain)
    elif args.file:
        check_file(args.file)
    else:
        help()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Wrong execution\n")
        help()
        sys.exit(0)

    print("-" * 20, "Checking if the domain is vulnerable", "-" * 20)

    main()
