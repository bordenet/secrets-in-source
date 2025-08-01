It's NOT okay to have passwords and other secrets littered across your codebase.
This simple go app makes detection quick and easy to locate them. From there, choose your own adventure.
The regular expressions included in the various .regex files in this repo are included as samples.

This project started as a bash shell script and was migrated to Go in collaboration with [danielgtaylor](https://github.com/danielgtaylor/danielgtaylor)

Ensure you run preliminary results by the included "test" directory to ensure all Positive test cases are detected + none of the False Positives test cases slip through. Add new test cases opportunistically. 

## Usage

This tool, passhog.go, is written in Go. It scans local directories for secrets based upon regular expressions. First, [install Go](https://go.dev/dl/), git clone this repo, and run:

```bash
# Navigate to the source
$ cd secrets-in-source

# Run the Go implementation
$ go run passhog.go <directory_path>

# Or build/install the Go implementation (make sure `~/go/bin` is in your PATH!)
$ go install
$ passhog <directory_path>

$ passhog <directory_path> --types=py,cs
$ passhog <directory_path> --output=./passhog_results.txt
$ passhog <directory_path> --types=yml,yaml,env,tf --output=./passhog_results.txt

```
That binary is self-contained & safe to bundle up and share with others. Want to cross compile? Just set some environment variables like `GOOS=windows GOARCH=amd64 go build` and you're good to go with `passhog.exe`.

**Concrete examples:**
```bash
pushd secrets-in-source > /dev/null
go run ./passhog.go /path/to/target --types=cs,py --output=passhog_results_cs_py.txt
less ./passhog_results_cs_py.txt
go run ./passhog.go /path/to/target
popd > /dev/null
```

## Test it

`go test` will execute a battery of tests using `test/Positives.txt` and `test/False_Positives` and the `.regex` regular expression files consumed by passhog.go

## How it works

Here's how we make the Go version fast:

1. Load and precompile all the regular expressions once.
2. Do not shell out or run additional processes requiring startup time.
3. Keep stats in memory, no temporary files.
4. Run up to `runtime.NumCPU()` concurrent goroutines to process files so we can take advantage of multiple cores.
5. Use a `bufio.Scanner` to read line-by-line so it interweaves file I/O & CPU (regex) workloads.

## Regex Files

The tool uses several regex pattern files for different purposes:

- **`direct_matches.regex`**: High-confidence patterns for common secrets
- **`fast_patterns.regex`**: Quick preliminary patterns used for initial filtering
- **`strict_patterns.regex`**: More thorough patterns used for final detection
- **`exclude_patterns.regex`**: Patterns to exclude false positives

The scanning process uses a two-stage approach: files are first screened with fast patterns, then more thoroughly analyzed with strict patterns, while exclude patterns filter out false positives.

## Alternative

trufflehog is an industry standard tool for secrets-in-source detection. It's slower than our Go implementation, but results are of extremely high quality. This tool is also designed to work against GitHub repos, directly.

`brew install trufflehog && trufflehog`

## Tune it

We consider trufflehog to be the industry-standard. There now exists a tool in the `test` subdirectory of this project which will compare results between the two tools. This will enable us to fine-tune the regular expressions until we get to within 10%, or so.  NOTE: passhog.go does not currently parse .zip files!

Assuming your git repo clones reside in a directory ~/GitHub:
```bash
trufflehog filesystem /Users/$(whoami)/GitHub --json  --concurrency=36 > trufflehog_all.json
go run ./passhog.go /Users/$(whoami)/GitHub --output=passhog_all.txt
pushd test
go run ./secrets_gap_analysis.go -t ../trufflehog_all.json -p ../passhog_all.txt
popd
```
## Improve it

When you detect a false-positive, you can add it as a test case to the bottom of `test/False_Positives.txt`. Then extend `exclude_patterns.regex` and re-run tests via `go test`

When you detect a missed secret, you can add it as a test case to the bottom of `test/Positives.txt`. Then extend one or more of the `.regex` files, e.g. `fast_patterns.regex` and `strict_patterns.regex`. Use `go test` to help narrow things down.

When tests are passing, submit a PR.

## License

This project is licensed under the MIT License – see the [LICENSE](./LICENSE) file for details.
