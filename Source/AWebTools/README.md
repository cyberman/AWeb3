# AWebTools - AWeb Test Suite

AWebTools is a collection of standalone test tools for testing AWeb functionality in isolation. This allows for easier debugging and testing of individual components without the complexity of the full AWeb application.

## Tools

### AWebGet

AWebGet is a comprehensive HTTP/network testing tool that exercises the complete set of networking functionality used by AWeb. It includes:

- HTTP/HTTPS request testing
- SSL/TLS connection testing
- Proxy support testing
- Cookie handling
- Authorization testing
- Detailed debugging output

#### Usage

```bash
# Run built-in test suite
AWebGet

# Test a specific URL
AWebGet -u http://example.com/

# Test HTTPS URL
AWebGet -u https://www.google.com/

# Show help
AWebGet -h
```

#### Features

- **Built-in Test Suite**: Tests various URLs including HTTP, HTTPS, and error cases
- **Custom URL Testing**: Test any URL with the `-u` or `--url` option
- **Detailed Output**: Comprehensive debugging information for network operations
- **SSL Support**: Full SSL/TLS testing capabilities
- **Error Handling**: Tests both successful and failed connections

#### Debug Output

AWebGet provides detailed debugging output including:

- TCP connection status
- HTTP request/response headers
- SSL cipher information
- Cookie handling
- Authorization requests
- Error conditions
- Data transfer statistics

## Building

To build the AWebTools:

```bash
cd aweb36/AWebTools
smake
```

This will compile AWebGet and all its dependencies.

## Dependencies

AWebGet requires:

- SAS/C compiler
- AmigaOS 3.2 or higher
- bsdsocket.library
- amissl.library (for SSL testing)

## Architecture

The AWebTools project is designed to be modular, allowing individual components of AWeb to be tested in isolation. Each tool focuses on a specific area:

- **Network Tools**: Test HTTP, SSL, and networking functionality
- **JavaScript Tools**: Test the JavaScript engine (planned)
- **Library Tools**: Test .aweblib libraries (planned)

## Future Tools

Planned tools for the AWebTools suite:

- **AWebJS**: JavaScript engine testing tool
- **AWebLibTest**: .aweblib library testing tool
- **AWebParser**: HTML/CSS parser testing tool

## Contributing

When adding new tools to AWebTools:

1. Create a new subdirectory for the tool
2. Add a smakefile for the tool
3. Include comprehensive debugging output
4. Add documentation to this README
5. Include test cases and examples

## License

AWebTools is part of the AWeb project and is licensed under the AWeb Public License. 