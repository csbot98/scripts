# Elasticsearch to IBM SOAR Automation Script

## Overview

This Python-based automation script connects to an Elasticsearch SIEM system, retrieves alert documents, and creates corresponding incidents in IBM Resilient SOAR. It streamlines security alert management by automatically forwarding relevant alerts from Elasticsearch to the SOAR platform, reducing manual work and improving incident response times.

## Main Features

- **Elasticsearch Integration:** Queries Elasticsearch using REST API to fetch alert documents based on specific rule names or tags.
- **Incident Deduplication:** Checks if an alert (by Alert ID) already exists in SOAR to prevent duplicate incident creation.
- **Payload Creation:** Constructs detailed incident payloads from Elasticsearch alert data, including severity mapping and artifact extraction.
- **Asynchronous Processing:** Handles multiple alerts concurrently for efficient data processing and API interaction.
- **Debug Mode:** Provides detailed logging and output to facilitate troubleshooting and development.

## Requirements

- Python 3.x
- Dependencies:
  - `aiohttp`
  - `elasticsearch`

Install dependencies with:

```bash
pip install aiohttp elasticsearch
