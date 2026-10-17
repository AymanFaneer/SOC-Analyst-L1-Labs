# Enterprise SOC Home Lab

A virtualized Security Operations Center (SOC) lab built to practice
**SOC Analyst Level 1 (L1)** skills, including log collection,
centralized monitoring, network segmentation, and foundational
investigation workflows.

This repository currently documents the infrastructure and SIEM
foundation. Attack simulations and their investigations will be added in
later phases.

## Project Objectives

-   Build a multi-network lab using VMware and pfSense Community
    Edition.
-   Separate employee endpoints, infrastructure servers, and an isolated
    lab network.
-   Deploy an Active Directory domain and join Windows endpoints.
-   Centralize Windows, Domain Controller, and Linux logs in Splunk
    Enterprise.
-   Validate log-forwarder communication and searchable event ingestion.
-   Document the setup and evidence for repeatability and portfolio
    review.

## Lab Architecture

  Component                Hostname / Role   IP address        Network
  ------------------------ ----------------- ----------------- ----------------------
  Firewall                 pfSense WAN       `192.168.8.137`   VMware WAN / NAT
  Firewall                 pfSense LAN       `10.10.10.1`      Employee LAN
  Firewall                 pfSense OPT1      `10.10.20.1`      Server network
  Firewall                 pfSense OPT2      `10.10.30.1`      Isolated lab network
  Windows endpoint         `SOC-WIN11`       `10.10.10.30`     Employee LAN
  Windows endpoint         `SOC-WIN02`       `10.10.10.31`     Employee LAN
  Linux endpoint           `SOC-UBUNTU`      `10.10.10.32`     Employee LAN
  Active Directory / DNS   `SOC-DC01`        `10.10.20.10`     Server network
  SIEM                     `SOC-SIEM`        `10.10.20.20`     Server network
  Test machine             Kali Linux        `192.168.8.131`   VMware WAN / NAT

**Active Directory domain:** `corp.soclab.test`

**Splunk services:** Splunk Web on TCP `8000`; forwarder receiving on
TCP `9997`.

> These are private lab addresses and test systems, not production
> infrastructure.

## VMware Infrastructure

The virtual environment is hosted in VMware. Separate virtual networks
are used to connect the employee endpoints, server infrastructure, and
isolated lab segment through pfSense.


## pfSense Firewall and Network Segmentation

pfSense Community Edition acts as the virtual firewall and router
between the lab networks. Firewall rules allow required services,
including domain services and log forwarding, while restricting
unnecessary traffic between segments.

-   **Employee LAN --- `10.10.10.0/24`:** Windows and Linux endpoints.
-   **Server network --- `10.10.20.0/24`:** Active Directory, DNS, and
    Splunk.
-   **Isolated lab network --- `10.10.30.0/24`:** Reserved for isolated
    scenarios in later labs.
-   **WAN / NAT network --- `192.168.8.0/24`:** VMware's upstream
    virtual network.

Connectivity and selected isolation behavior were tested during setup.


## Active Directory

The domain controller `SOC-DC01` provides Active Directory Domain
Services and DNS for `corp.soclab.test`. Windows endpoints `SOC-WIN11`
and `SOC-WIN02` are joined to the domain.

Validation included domain-controller discovery and secure-channel
checks from the Windows endpoints.


## Splunk SIEM

Splunk Enterprise is deployed on `SOC-SIEM` at `10.10.20.20`. Universal
Forwarders send events to the Splunk receiving port (`9997`).

The current setup collects logs from four systems:

  Host                              Log source / index
  --------------------------------- -----------------------------------------
  `SOC-WIN11`                       Windows events --- `windows`
  `SOC-WIN02`                       Windows events --- `windows`
  `SOC-DC01`                        Domain Controller events --- `soc_dc01`
  `ayman-VMware-Virtual-Platform`   Linux events --- `linux`

The environment was checked to confirm that events were arriving from
all four systems. Windows Security collection includes events such as
successful and failed logons, where available.


## Validation Performed

-   Confirmed that domain-joined Windows endpoints could discover the
    domain controller.
-   Checked the Windows secure channel.
-   Verified Splunk Web access from intended lab systems.
-   Confirmed that forwarders were connected and events were searchable
    in Splunk.
-   Tested selected network-isolation rules and reviewed firewall
    behavior.

## Next Steps

This infrastructure and log-collection foundation will support realistic
SOC L1 scenarios. Planned work includes generating controlled security
events, creating and testing Splunk detections, investigating alerts,
and documenting evidence, analysis, and incident verdicts for each
scenario.

All testing will be performed in the home lab, with a focus on defensive
monitoring and investigation.

## Disclaimer

This is an educational home lab. Systems, addresses, and activity are
simulated or lab-contained. No testing is intended against systems
without authorization.
