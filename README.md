# Popsql

![Uploading logo popsql.png…]()

 
This Go script, pop_sql.go, is designed to scan a list of URLs to identify potential SQL injection vulnerabilities. The script performs these checks by manipulating URLs and observing responses to detect signs of SQL injection attacks.

The script is named popsql because "pop" comes from the nickname "repop" given to me by a friend lol.

Install Command
go install github.com/bariqahay/Popsql@latest

Key Components

    Imports:
        The script imports necessary packages such as bufio, flag, fmt, io, log, net/http, net/url, os, strings, sync, sync/atomic, and time.

    Global Variables:
        urlsfile: Path to the file containing URLs to be scanned.
        urls: Slice to store URLs read from the file.
        workers: Number of parallel workers for scanning (default: 5).
        timeout: Timeout for HTTP requests in seconds (default: 10).
        delay: Delay between requests in seconds (default: 0.5).
        outputFile: Path to the file where results will be saved (default: vulnerable_urls.txt).

    Initialization:
        The init function initializes command-line flags for configuring the script.

    Banner:
        The printBanner function prints a banner to the console for visual identification of the script.

    File Extension Check:
        The isFileExtension function determines if a URL ends with a common file extension that typically does not require SQL injection testing.

    SQL Injection Check:
        The checkSQLInjection function performs the main SQL injection detection:
            Query Parameters: Modifies query parameters to include SQL injection payloads and sends requests. Checks for HTTP 500 errors or SQL error messages in the response body.
            URLs without Query Parameters: Appends a SQL injection payload to URLs and sends requests to detect vulnerabilities.

    SQL Keywords Detection:
        The containsSQLKeywords function scans the response body for common SQL error messages or keywords that indicate SQL injection vulnerabilities.

    Main Function:
        Command-Line Arguments: Parses command-line arguments for configuration.
        File Handling: Opens and reads the file containing URLs.
        Concurrent Scanning: Uses goroutines and a semaphore pattern to manage concurrent URL scanning.
        Results Handling: Writes detected vulnerable URLs to the specified output file.

Usage

The script is executed from the command line with the following options:

    -urlsfile <file_with_urls>: Path to the file containing URLs to be scanned.
    -t <workers>: Number of parallel workers (default is 5).
    -timeout <seconds>: HTTP request timeout in seconds (default is 10).
    -p <delay>: Delay between requests in seconds (default is 0.5).
    -o <output_file>: File to save the results of detected vulnerable URLs (default is vulnerable_urls.txt).
