# Contributing to SIEM Project

Thank you for your interest in contributing to our SIEM (Security Information and Event Management) system! We welcome contributions from the community.

## 🤝 How to Contribute

### Reporting Issues

1. **Search existing issues** first to avoid duplicates
2. **Use the issue template** when creating new issues
3. **Provide detailed information** including:
   - Operating system and version
   - Python version
   - Docker version
   - Steps to reproduce
   - Expected vs actual behavior
   - Log files (sanitized of sensitive data)

### Submitting Pull Requests

1. **Fork the repository**
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following our coding standards
4. **Test your changes** thoroughly
5. **Update documentation** if needed
6. **Submit a pull request** with a clear description

## 🛠️ Development Setup

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Git

### Local Development

1. **Clone your fork**:
   ```bash
   git clone https://github.com/yourusername/siem.git
   cd siem
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # If available
   ```

4. **Set up environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Start development services**:
   ```bash
   docker-compose up -d postgres redis elasticsearch
   ```

6. **Run the application**:
   ```bash
   python -m siem.main
   ```

## 📝 Coding Standards

### Python Style Guide

- Follow **PEP 8** style guidelines
- Use **type hints** for function parameters and return values
- Write **docstrings** for all classes and functions
- Use **meaningful variable names**
- Keep functions **small and focused**

### Code Formatting

We use the following tools for code formatting:

```bash
# Install formatting tools
pip install black isort flake8 mypy

# Format code
black .
isort .

# Check style
flake8 .
mypy .
```

### Example Code Style

```python
from typing import Optional, List, Dict, Any
from datetime import datetime

class SecurityEvent:
    """Represents a security event in the SIEM system.
    
    Args:
        event_type: Type of security event
        severity: Severity level (low, medium, high, critical)
        timestamp: When the event occurred
        source_ip: Source IP address if applicable
    """
    
    def __init__(
        self,
        event_type: str,
        severity: str,
        timestamp: Optional[datetime] = None,
        source_ip: Optional[str] = None
    ) -> None:
        self.event_type = event_type
        self.severity = severity
        self.timestamp = timestamp or datetime.utcnow()
        self.source_ip = source_ip
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip
        }
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=siem

# Run specific test file
pytest tests/test_collectors.py

# Run tests with verbose output
pytest -v
```

### Writing Tests

- Write tests for all new functionality
- Use descriptive test names
- Include both positive and negative test cases
- Mock external dependencies
- Aim for high test coverage

### Test Structure

```python
import pytest
from unittest.mock import Mock, patch
from siem.collectors.syslog_collector import SyslogCollector

class TestSyslogCollector:
    """Test cases for SyslogCollector."""
    
    def test_parse_valid_syslog_message(self):
        """Test parsing a valid syslog message."""
        collector = SyslogCollector({"api_url": "http://test"})
        raw_message = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        
        result = collector.parse_event(raw_message)
        
        assert result is not None
        assert result.event_type == "failed_login"
        assert result.severity == "medium"
    
    @patch('httpx.AsyncClient.post')
    async def test_flush_events_success(self, mock_post):
        """Test successful event flushing."""
        mock_post.return_value.status_code = 200
        
        collector = SyslogCollector({"api_url": "http://test"})
        # Add test implementation
```

## 📚 Documentation

### Code Documentation

- Use **docstrings** for all public classes and methods
- Follow **Google docstring format**
- Include **examples** in docstrings when helpful
- Document **complex algorithms** with inline comments

### README Updates

When adding new features:

1. Update the main README.md
2. Add configuration examples
3. Update the feature list
4. Include usage examples

## 🔒 Security Considerations

### Sensitive Data

- **Never commit** secrets, passwords, or API keys
- Use **environment variables** for configuration
- **Sanitize logs** before sharing
- **Review code** for potential security issues

### Security Testing

- Test for **SQL injection** vulnerabilities
- Validate **input sanitization**
- Check **authentication** and **authorization**
- Test **rate limiting** and **DoS protection**

## 🎯 Areas for Contribution

We welcome contributions in these areas:

### High Priority
- **New log collectors** (Windows Event Log, CEF, LEEF)
- **Detection rules** for specific threats
- **Performance optimizations**
- **Test coverage improvements**
- **Documentation enhancements**

### Medium Priority
- **Machine learning** anomaly detection
- **Advanced correlation** algorithms
- **Integration** with external systems
- **Mobile dashboard** application
- **Kubernetes deployment** manifests

### Low Priority
- **UI/UX improvements**
- **Additional export formats**
- **Compliance reporting**
- **Multi-tenancy support**

## 🏷️ Issue Labels

We use the following labels to categorize issues:

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Improvements or additions to docs
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention is needed
- `security` - Security-related issues
- `performance` - Performance improvements
- `collector` - Related to log collectors
- `detection` - Related to detection rules
- `api` - Related to REST API
- `dashboard` - Related to web dashboard

## 🎉 Recognition

Contributors will be:

- **Listed** in the README.md contributors section
- **Mentioned** in release notes for significant contributions
- **Invited** to join the maintainers team for consistent contributors

## 📞 Getting Help

If you need help:

1. **Check the documentation** first
2. **Search existing issues** and discussions
3. **Join our community** (Discord/Slack if available)
4. **Create an issue** with the `help wanted` label

## 📋 Pull Request Checklist

Before submitting a pull request, ensure:

- [ ] Code follows the style guidelines
- [ ] Tests are written and passing
- [ ] Documentation is updated
- [ ] Commit messages are clear and descriptive
- [ ] No sensitive data is included
- [ ] Changes are backward compatible (or breaking changes are documented)
- [ ] Performance impact is considered
- [ ] Security implications are reviewed

## 🔄 Release Process

1. **Version bumping** follows semantic versioning
2. **Changelog** is updated for each release
3. **Testing** is performed on staging environment
4. **Docker images** are built and published
5. **GitHub releases** include detailed notes

Thank you for contributing to making cybersecurity better! 🛡️