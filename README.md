# Proof-of-Concept (PoC) Attacks

This repository contains the PoC attacks for the paper "MEGA: Malleable Encryption Goes Awry". See [our website](https://mega-awry.io) for more details.  

:warning: This code is only intended to make our attacks reproducible. You should never run the attacks against any account that you do not own. Furthermore, it is the responsibility of the person executing the code in this repo to ensure they never put any disproportionate stress on MEGA's infrastructure, e.g., by spamming login requests. The code is provided without any guarantees and the person running the code bears all responsibility.

## Overview

This repository contains PoCs for the following five attacks on the cryptographic design of MEGA:
1. [RSA key recovery](issue_01): combines key overwriting with a chosen-plaintext attack to factor the RSA modulus in 683 login queries.
2. [AES-ECB plaintext recovery](issue_02): recovers the plaintext of two AES blocks encrypted with AES-ECB under the master key. In MEGA's architecture, this affects signing keys, asymmetric chat keys, and node encryption keys using an adaption of the RSA key recovery attack.
3. [Framing attack](issue_03): uses the AES-ECB plaintext recovery to place a largely chosen file (except for one AES block) in a victim's cloud, which is indistinguishable from genuinely uploaded data.
4. [Integrity attack](issue_04): uses a single known AES-ECB plaintext-ciphertext pair to construct a file ciphertext which passes integrity protection and uses a key of all zero bytes.
5. [Guess-and-Purge Bleichenbacher attack variant](issue_05): motivated by MEGA's custom RSA padding, we provide a more generic description of Bleichenbacher's attack on PKCS#1 v1.5 that can tolerate small unknown prefix values.

## Code Organization

Our proof of concepts (PoCs) run in one of two settings, depending on the attack scenario:
1. _abstract_: The attacker uses our simulation of MEGA. (This setting is called _sim_ in the paper.)
2. _mitm_: The attacker runs a TLS-MitM setup with an HTTPS proxy to intercept traffic between the client and the server. (This setting is called _real_ in the paper.)

The former captures the scenario where the adversary controls MEGA's core infrastructure and, therefore, has access to the code of MEGA's servers.
This is simulated in the PoC's, since we do not actually have access to the servers.

The _mitm_ setting requires a more sophisticated setup with additional dependencies. We remark below which dependencies are only needed for _mitm_, and the attack in _abstract_ can be run without the installation of these additional dependencies.

The code contains detailed comments on the attacks and structure.

## Prerequisites

### General Dependencies

The following dependencies are required (or useful) for running attacks in general (both the abstract and the MitM attacks).

#### Python Packages

Install:
```
pip3 install pycryptodome
```

#### Sagemath

> This installation is optional. The attacks are functional without Sagemath, but slower.

For the lattice attacks of the RSA key recovery attack, [Sage](https://doc.sagemath.org/html/en/installation/) needs to be installed (and linked to the Python executable that you use to run `run_poc.py`).

### MitM Dependencies

The following dependencies are only necessary to run the MitM attacks.

#### mitmproxy

Running the Man-in-the-Middle (MitM) attacks of this project requires installing and configuring [mitmproxy](https://mitmproxy.org/) on your device.

The best way to do this is over `pip`:
```
pip3 install mitmproxy==7.0.4
```

#### Selenium

[Install Selenium](https://www.selenium.dev/documentation/webdriver/getting_started/) for browser automation.

You need to install the [Python bindings for the Selenium WebDriver](https://pypi.org/project/selenium/):
```text
pip install selenium
```

And the [browser drivers](https://www.selenium.dev/documentation/webdriver/getting_started/install_drivers/) to allow your browser to be automated.


### MitM Extra Preparation

Apart from installing the MitM dependencies, you also need to prepare a victim account to run the MitM PoC code.
This involves adding private account information in [shared/constants/victim.py](shared/constants/victim.py).
The places that require modification are marked with a `TODO`.
This private information is used as intermediate results to make chained attacks easier and avoid having to re-run previous attacks.
For instance, the AES-ECB plaintext recovery attack uses the RSA key of the test account directly instead of recovering it from the ground (e.g., using the attack described in Issue 01).

#### Prepare an Account

We advise to set up a new MEGA account to test the PoC attacks.

The following might be helpful when extracting the target account information for [shared/constants/victim.py](shared/constants/victim.py):
1. One can obtain secret key information (including RSA key information, the master key, and a file handle) by modifying the [MEGAcli](https://github.com/meganz/sdk/blob/master/examples/megacli.cpp) command line utility that is included as an example in [MEGA's SDK](https://github.com/meganz/sdk).
  - The master key is equal to the recovery key, which can be exported in the GUI.
  - A users public key and file handles are also visible in the network communication during login. You can use your browsers developer tools to find them.
2. Pay attention that the primes `p` and `q` are set in the right order. The value `u` needs to be the inverse of `q` modulo `p`. If the attacks do not work, try to switch `p` and `q`.
3. If you set up a new account (which you should), finish the account setup and close all pop-up windows (initial help, copyright information on first sharing, etc.). Otherwise, the automated browser of the victim might fail to perform the steps required for the PoCs.
4. Activate the setting to wipe all data at logout. It is a radio button called `Log out options` under `Settings` in the `Metadata` section.


## How to Run

You can run all PoCs using the script `run_poc.py`. Some attacks have a MitM implementation, which requires more a more sophisticated setup (with `mitmproxy` and `Selenium`). You can only run the attacks that use a simulated version of MEGA by using the `--abstract` flag. By default, all attacks (on both types and for all issues) are run.

Help page of the entry point script `run_poc.py`:
```text      
usage: run_poc.py [-h] [-i ISSUE] [-a] [-m]

Run PoCs

optional arguments:
  -h, --help            show this help message and exit
  -i ISSUE, --issue ISSUE
                        Specify which issue to run
  -a, --abstract        Only run abstract PoC
  -m, --mitm            Only run mitm PoC
```

## Log Files

The log file `mitmproxy.log`, written to the current working directory (which should be the root of this repo), stores intermediate results of the attacks. For instance, the current interval for the binary search of Issue 1 is logged there. This allows one to observe that the attack correctly recovers the first few bits of the RSA factor and abort the attack to avoid causing high traffic on production servers (see [our PoC video](https://mega-awry.io/#rsa-key-recovery)).
