# Contributing to Rekor Log Verification

Follow this guide to contribute to this repository.

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/ssannkkallpp/cs-9223-assignment-1.git
cd cs-9223-assignment-1
```

### 2. Set Up Dependencies

**Using pip:**
```bash
pip3 install -r requirements.txt
```

**Using Poetry (recommended for development):**
```bash
poetry install --with dev
```

Run tests:
```bash
pytest
```

## Opening Issues

Before creating an issue, please search existing issues to avoid duplicates.

When opening an issue, please include:
- **Bug reports**: Steps to reproduce, expected vs. actual behavior, error messages
- **Feature requests**: Use case, proposed solution, alternatives considered and why it is needed

## Submitting Pull Requests

1. **Create a new branch from `main`**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the existing code style

3. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Open a pull request** with:
   - A clear title and description
   - Reference to any related issues
   - Summary of changes made
   - Test coverage status


## Questions?

Feel free to open an issue for any questions about contributing!
