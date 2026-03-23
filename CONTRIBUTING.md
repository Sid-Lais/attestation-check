# Contributing to tee-verify

Thank you for your interest in contributing to tee-verify! This project is maintained by [ORGN](https://orgn.com) and we welcome contributions from the community.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/tee-verify.git`
3. Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`
4. Install in development mode: `pip install -e ".[dev]"`
5. Run the tests: `pytest tests/ -v`

## Development Workflow

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes
3. Run the linter: `ruff check src/ tests/`
4. Run the tests: `pytest tests/ -v`
5. Commit your changes with a clear message
6. Push to your fork and open a pull request

## Code Style

- We use [ruff](https://github.com/astral-sh/ruff) for linting
- Target Python 3.9+
- Line length limit: 100 characters
- Write tests for all new functionality

## Reporting Issues

- Use GitHub Issues to report bugs
- Include Python version, OS, and full error output
- If reporting a verification failure, include the attestation data (if public)

## Security

If you discover a security vulnerability, please report it responsibly by emailing security@orgn.com instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
