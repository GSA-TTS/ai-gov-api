# Integration Test Inventory

## Overview
This document provides a comprehensive inventory of all integration test files in the GSAi API Testing Framework.

### Summary Statistics
- **Total Test Files**: 146
- **Total Test Cases**: 1,259

### Test Distribution by Section

| Section | Number of Files | Description |
|---------|----------------|-------------|
| 7.12 Zero Trust | 31 | Zero Trust Architecture and security testing |
| 7.2 Functional | 14 | Functional and validation testing |
| 7.3 Security | 45 | Security testing (OWASP API Top 10, etc.) |
| 7.4 Performance | 12 | Performance and load testing |
| 7.5 Reliability | 23 | Reliability and error handling |
| 7.9 Data Management | 21 | Data management and privacy testing |

## Package Usage Analysis

### Most Common Third-Party Packages
1. **pytest** - Used in all test files (core testing framework)
2. **httpx** - Used in 145 files (async HTTP client)
3. **faker** - Used in 5 files (test data generation)
4. **psutil** - Used in 7 files (system monitoring)
5. **numpy/scipy/sklearn** - Used in specialized tests

### Most Common Standard Library Packages
1. **asyncio** - Used in 124 files
2. **typing** modules (Dict, Any, List) - Used in most files
3. **dataclasses** - Used in 143 files
4. **json** - Used in 124 files
5. **time** - Used in 94 files

## Test Inventory Structure

The complete test inventory is available in `inventory.json` with the following structure:

```json
{
  "/path/to/test_file.py": {
    "packages": ["list", "of", "imported", "packages"],
    "test_cases": ["test_method_001", "test_method_002", ...]
  }
}
```

### Example Entry
```json
{
  "/Users/tamnguyen/Documents/GitHub/ai-gov-api/tests/integration/7_2_functional/test_input_validation.py": {
    "packages": [
      "pytest", "httpx", "asyncio", "json", "typing.Dict", 
      "typing.Any", "dataclasses", "sys", "pathlib.Path", 
      "config.config", "config.logger"
    ],
    "test_cases": [
      "test_tdm_inputval_stringlength_001",
      "test_tdm_inputval_numericrange_002",
      "test_tdm_inputval_emailformat_003",
      "test_tdm_inputval_dateformat_004",
      "test_tdm_inputval_enumvalidation_005",
      "test_tdm_inputval_complexobjects_006",
      "test_tdm_inputval_arraybounds_007",
      "test_tdm_inputval_optionalfields_008",
      "test_tdm_inputval_nesting_009",
      "test_tdm_inputval_sanitization_010"
    ]
  }
}
```

## Key Insights

1. **Minimal Dependencies**: Despite having 200+ packages in requirements.txt, only 11 third-party packages are actually used.

2. **Consistent Structure**: All test files follow a consistent pattern with similar imports and test naming conventions.

3. **Comprehensive Coverage**: The test suite covers all major aspects of API testing including security, performance, reliability, and data management.

4. **Test ID Convention**: Most test cases follow a naming convention like `test_CATEGORY_SUBCATEGORY_ID_###` which makes them easy to identify and track.

## Usage

To access the complete inventory programmatically:

```python
import json

with open('inventory.json', 'r') as f:
    inventory = json.load(f)

# Example: Get all test cases for a specific file
file_path = "/path/to/test_file.py"
test_cases = inventory[file_path]["test_cases"]
packages = inventory[file_path]["packages"]
```

## Files Generated

1. **inventory.json** - Raw JSON inventory of all test files
2. **inventory_formatted.json** - Pretty-printed version for readability
3. **test_inventory.md** - This documentation file

Last Updated: January 2025