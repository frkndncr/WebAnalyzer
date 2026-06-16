# Contributing to WebAnalyzer

First off, thank you for considering contributing to WebAnalyzer! It's people like you who make WebAnalyzer such a powerful and versatile tool for the community.

Please take a moment to review this document to make the contribution process smooth and effective for everyone.

---

## 🗺️ How Can I Contribute?

### 🐛 Reporting Bugs
* **Search first**: Check existing issues to see if the bug has already been reported.
* **Open an issue**: If you find a new bug, open an issue using the Bug Report template.
* **Include details**: Provide a clear description, steps to reproduce, expected vs. actual behavior, and log outputs.

### 💡 Suggesting Enhancements
* **Open a feature request**: Describe the feature you want, why it is useful, and how it should work.
* **Discuss**: Participate in discussions to refine feature specs before writing code.

### 🔧 Submitting Pull Requests (PRs)
1. **Fork the Repository**: Create your own fork of the project.
2. **Create a Branch**: Create a feature branch off `main` (e.g., `feature/dynamic-waf-bypass`).
3. **Write Tests**: Ensure your code changes compile and include unit tests in the `tests/` directory where applicable.
4. **Follow Code Style**: We adhere to PEP 8 style guidelines for Python code.
5. **Open a PR**: Submit a pull request to our `main` branch with a clear description of your changes.

---

## 💻 Developer Setup Guide

To set up a local development environment:

### 1. Clone your Fork
```bash
git clone https://github.com/your-username/WebAnalyzer.git
cd WebAnalyzer
```

### 2. Set up a Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate on Windows
.\venv\Scripts\activate

# Activate on Linux/macOS
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Running the Test Suite
Before committing any changes, run the Python compilation checks and tests to verify nothing is broken:
```bash
# Run syntax compilation checks
python -m py_compile main.py api.py bulk/processor.py database/db_manager.py

# Run unit tests
python -m unittest discover -s tests
```

---

## 📜 Pull Request Guidelines

* **Keep PRs focused**: A single PR should address a single issue or implement a single feature.
* **Write meaningful commit messages**: Write clean, imperative-style commit messages (e.g., `feat: add DNSSEC validation to DNS module`).
* **Update documentation**: If you add new parameters or modify CLI flags, update both `README.md` and `README.TR.MD`.
* **Be responsive**: Engage in code reviews and address feedback promptly.

Thank you for helping make WebAnalyzer the best OSINT and domain security tool on GitHub! 🚀
