<p align="center">
  <a href="https://openlv.sh">
    <picture>
      <source srcset="https://raw.githubusercontent.com/v3xlabs/open-lavatory/refs/heads/master/docs/public/openlv_logo_dark.svg" media="(prefers-color-scheme: dark)">
      <img src="https://raw.githubusercontent.com/v3xlabs/open-lavatory/refs/heads/master/docs/public/openlv_logo_light.svg" alt="Open Lavatory" width="auto" height="60">
    </picture>
  </a>
</p>

<p align="center">
  Secure peer-to-peer connectivity between dApps and wallets
</p>

<p align="center">
    <a href="https://openlv.sh"><img src="https://img.shields.io/badge/Documentation-openlv.sh-orange?style=flat" alt="Documentation: openlv.sh"></a>
    <a href="#"><img src="https://img.shields.io/badge/Status-In%20Development-blue?style=flat" alt="Status: In Development"></a>
    <a href="#"><img src="https://img.shields.io/badge/Tests-Passing-lime?style=flat&color=63ba83" alt="Tests: Passing"></a>
    <a href="#"><img src="https://img.shields.io/badge/License-LGPL--3.0-hotpink?style=flat" alt="License: LGPL-3.0"></a>
</p>

---

## Features

- Privacy-first, end-to-end encrypted, no metrics, no tracking
- No central dependency, rather a variety of [signaling layers](https://openlv.sh/api/signaling)
- Peer-to-peer transport via WebRTC (or other [transport layers](https://openlv.sh/api/transport))
- Reuse of existing infrastructure and p2p standards
- User control over connection & configuration

## Quickstart

```bash
[dependencies]
openlv = "0.0.2"
```

## Overview

A secure privacy-first protocol for establishing peer-to-peer JSON-RPC connectivity between decentralized applications (dApps) and cryptocurrency wallets.

Open Lavatory Protocol eliminates centralized relay servers by enabling direct peer-to-peer connections between decentralized applications (dApps) and cryptocurrency wallets. Using public signaling servers for initial handshake and WebRTC combined with asymmetric encryption, it prioritizes **privacy** and **self-sovereignty**.

## Documentation

[Head to the documentation](https://openlv.sh) to learn more about openlv.

## Repository Structure

This repository includes the following packages:

| Package                                                                                                                 | Description |
| ----------------------------------------------------------------------------------------------------------------------- | ----------- |
| [openlv](./crates/openlv) [![crates](https://img.shields.io/crates/v/openlv.svg?color=orange)](https://crates.io/crates/openlv) |             |

| Examples                    | Description |
| --------------------------- | ----------- |
| [wallet](./examples/client) |             |
| [dapp](./examples/app)      |             |
