package main

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

var (
    urlsfile   string
    urls       []string
    workers    int
    timeout    int
    delay      float64
    outputFile string
)

func init() {
    flag.StringVar(&urlsfile, "urlsfile", "", "File with URLs to scan")
    flag.IntVar(&workers, "t", 5, "Number of parallel workers (default 5)")
    flag.IntVar(&timeout, "timeout", 10, "Request timeout in seconds (default 10)")
    flag.Float64Var(&delay, "p", 0.5, "Delay between requests in seconds (default 0.5)")
    flag.StringVar(&outputFile, "o", "vulnerable_urls.txt", "Output file to save vulnerable URLs")
}

func printBanner() {
    fmt.Println(`
  _____   ____  _____   _____  ____  _      
 |  __ \ / __ \|  __ \ / ____|/ __ \| |     
 | |__) | |  | | |__) | (___ | |  | | |     
 |  ___/| |  | |  ___/ \___ \| |  | | |     
 | |    | |__| | |     ____) | |__| | |____ 
 |_|     \____/|_|    |_____/ \___\_\______|
    `)
}

func isFileExtension(urlStr string) bool {
    // List of common file extensions
    extensions := []string{".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".pdf", ".txt", ".html", ".xml", ".csv"}
    for _, ext := range extensions {
        if strings.HasSuffix(urlStr, ext) {
            return true
        }
    }
    return false
}

func checkSQLInjection(urlStr string, wg *sync.WaitGroup, progress *uint32, total int, results chan<- string, sem chan struct{}) {
    defer wg.Done()
    defer func() { <-sem }() // Release semaphore when done

    // Check for file extension before proceeding
    if isFileExtension(urlStr) {
        return // Skip this URL, no logging
    }

    client := http.Client{
        Timeout: time.Duration(timeout) * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            // Prevents following redirects
            return http.ErrUseLastResponse
        },
    }

    // Check URL with query parameters
    parsedURL, err := url.Parse(urlStr)
    if err != nil {
        log.Printf("Error parsing URL %s: %v", urlStr, err)
        return
    }
    queryParams := parsedURL.Query()

    if len(queryParams) > 0 {
        // URL with query parameters
        for param := range queryParams {
            modifiedParams := make(url.Values)
            for k, v := range queryParams {
                if k == param {
                    for _, val := range v {
                        modifiedParams.Add(k, val+"'")
                    }
                } else {
                    for _, val := range v {
                        modifiedParams.Add(k, val)
                    }
                }
            }

            parsedURL.RawQuery = modifiedParams.Encode()
            modifiedURL := parsedURL.String()

            resp, err := client.Get(modifiedURL)
            if err != nil {
                log.Printf("Error getting URL %s: %v", modifiedURL, err)
                continue
            }
            defer resp.Body.Close()

            if resp.StatusCode == http.StatusInternalServerError {
                log.Printf("Possible SQL injection vulnerability detected: %s", modifiedURL)
                results <- modifiedURL
            } else if resp.StatusCode == http.StatusOK {
                body, err := io.ReadAll(resp.Body)
                if err != nil {
                    log.Printf("Error reading response body for URL %s: %v", modifiedURL, err)
                    continue
                }

                if containsSQLKeywords(body) {
                    log.Printf("Possible SQL injection vulnerability detected: %s", modifiedURL)
                    results <- modifiedURL
                }
            }

            time.Sleep(time.Duration(delay * float64(time.Second)))
        }
    } else {
        // URL without query parameters
        modifiedURL := urlStr + "'"
        resp, err := client.Get(modifiedURL)
        if err != nil {
            log.Printf("Error getting URL %s: %v", modifiedURL, err)
            return
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusInternalServerError {
            log.Printf("Possible SQL injection vulnerability detected: %s", modifiedURL)
            results <- modifiedURL
        } else if resp.StatusCode == http.StatusOK {
            body, err := io.ReadAll(resp.Body)
            if err != nil {
                log.Printf("Error reading response body for URL %s: %v", modifiedURL, err)
                return
            }

            if containsSQLKeywords(body) {
                log.Printf("Possible SQL injection vulnerability detected: %s", modifiedURL)
                results <- modifiedURL
            }
        }
    }

    atomic.AddUint32(progress, 1)
    fmt.Printf("Processed %d/%d URLs\n", *progress, total)
}

func containsSQLKeywords(body []byte) bool {
    sqlKeywords := []string{
        "SQL syntax",
        "mysql_fetch_array()",
        "ORA-",
        "SQLITE_ERROR",
        "SQLSTATE",
        "syntax error",
        "error near",
        "ERROR:",
        "syntax error at or near",
    }

    bodyText := string(body)

    for _, keyword := range sqlKeywords {
        if strings.Contains(bodyText, keyword) {
            return true
        }
    }
    return false
}

func main() {
    printBanner()
    flag.Parse()

    if urlsfile == "" {
        log.Fatal("Usage: popsql -urlsfile <file_with_urls> [-t workers] [-timeout seconds] [-p delay] [-o output_file]")
    }

    file, err := os.Open(urlsfile)
    if err != nil {
        log.Fatal("Error opening file: ", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        urls = append(urls, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        log.Fatal("Error reading file: ", err)
    }

    var wg sync.WaitGroup
    var progress uint32
    sem := make(chan struct{}, workers)

    out, err := os.Create(outputFile)
    if err != nil {
        log.Fatal("Error creating output file: ", err)
    }
    defer out.Close()

    results := make(chan string)

    go func() {
        for result := range results {
            if _, err := out.WriteString(result + "\n"); err != nil {
                log.Println("Error writing to output file: ", err)
            }
        }
    }()

    for _, urlStr := range urls {
        sem <- struct{}{}
        wg.Add(1)
        go checkSQLInjection(urlStr, &wg, &progress, len(urls), results, sem)
    }

    wg.Wait()
    close(results)

    fmt.Println("Scan completed.")
}
