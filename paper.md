---
title: "An Enhanced MQTT Communication Protocol for Privacy Preservation in Industrial Internet of Things (IIoT) Systems"
tags:
  - MQTT
  - IIoT
  - Secure Communication
  - AES Encryption
  - OTP Authentication
  - Python
  - GUI
authors:
  - name: "Ekeh Chioma Goodness"
    orcid: 0009-0006-0478-078X
    affiliation: 1
  - name: "Onwuachu Uzochukwu Christian"
  - affiliation: 1
affiliations:
  - name: "Department of Computer Science, Imo State University"
    index: 1
date: 2025-07-11
bibliography: paper.bib
---

# Summary

Secure-MQTT-IIoT is a Python-based, privacy-preserving communication framework built for Industrial Internet of Things (IIoT) systems. It enhances the traditional MQTT protocol with modern security mechanisms, including AES-128 encryption in CBC mode, HMAC verification, one-time password (OTP) verification, and role-based topic access. The system offers both publishing and subscribing modules, supported by a user-friendly GUI implemented using Tkinter.

Key features include:

- Encrypted login, publish, and subscribe operations
- OTP-based authentication (with cooldown, expiration)
- Password lockout after failed attempts
- Role-based access to MQTT topics (admin, sensor, viewer)
- Audit trail logging for login and message events

This system addresses the gap between lightweight messaging and secure communication in IIoT environments, particularly useful for research, simulation, or small-scale deployments.

# Statement of Need

In IIoT environments, data privacy and system integrity are critical. Standard MQTT lacks authentication and encryption features, exposing industrial systems to spoofing and eavesdropping. Secure-MQTT-IIoT offers a lightweight, open-source solution to this problem by adding security features tailored for constrained industrial devices. This project benefits both researchers and developers working on privacy-aware protocols, IoT simulations, and educational tools in cybersecurity and IoT networking.

# Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/Chiomaekeh/Secure-mqtt-iiot
cd Secure-mqtt-iiot
pip install -r requirements.txt
```

Ensure you have Mosquitto MQTT broker running on localhost (default port 1883).

# Usage

To run the publisher interface:

```bash
python publisher.py
```

To run the subscriber interface:

```bash
python subscriber.py
```

Users can register, receive OTP verification, log in, and securely publish or subscribe to MQTT messages based on their roles. Audit logs are maintained for each event.

# Acknowledgements

This project was developed as part of a Master's research project focused on secure communication protocols in Industrial Internet of Things (IIoT).

# References

See `paper.bib` for background references on MQTT, AES encryption, IIoT communication, and secure messaging frameworks.
