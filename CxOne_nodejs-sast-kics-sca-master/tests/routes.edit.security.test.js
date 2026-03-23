const tap = require('tap');
const http = require('http');
const express = require('express');
const routes = require('../routes');

tap.test('Edit route - Command Injection Prevention', (t) => {

  t.test('should reject invalid MongoDB ObjectID format', (t) => {
    // Test various command injection attempts and invalid IDs
    const invalidIds = [
      '; ls -la',                    // Command injection attempt
      '| cat /etc/passwd',          // Pipe command injection
      '$(whoami)',                  // Command substitution
      '`whoami`',                   // Backtick command substitution
      '../../../etc/passwd',        // Path traversal
      '12345',                      // Too short
      'invalid-id-format',          // Invalid characters
      'g23456789012345678901234',   // Invalid hex (contains 'g')
      '123456789012345678901234567', // Too long
      '',                           // Empty string
      null,                         // Null value
    ];

    let testCount = 0;
    const app = createTestApp();
    const server = app.listen(0, () => {
      const port = server.address().port;

      invalidIds.forEach((id) => {
        const encodedId = encodeURIComponent(id || '');
        http.get(`http://localhost:${port}/edit/${encodedId}`, (res) => {
          t.equal(res.statusCode, 400, `Should reject invalid ID: "${id}"`);

          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            t.match(data, /Invalid ID format/, `Should return error message for ID: "${id}"`);
            testCount++;
            if (testCount === invalidIds.length) {
              server.close();
              t.end();
            }
          });
        }).on('error', (err) => {
          t.fail(`Request failed: ${err.message}`);
          server.close();
          t.end();
        });
      });
    });
  });

  t.test('should accept valid MongoDB ObjectID format', (t) => {
    // Valid 24-character hexadecimal ObjectIDs
    const validIds = [
      '507f1f77bcf86cd799439011',
      '507f191e810c19729de860ea',
      'aaaaaaaaaaaaaaaaaaaaaaaa',
      'FFFFFFFFFFFFFFFFFFFFFFFF',
      '123456789abcdef012345678',
    ];

    let testCount = 0;
    const app = createTestApp();
    const server = app.listen(0, () => {
      const port = server.address().port;

      validIds.forEach((id) => {
        http.get(`http://localhost:${port}/edit/${id}`, (res) => {
          // Should not return 400 (bad request) for valid IDs
          // May return 500 if database is not connected, but that's OK for this test
          t.notEqual(res.statusCode, 400, `Should accept valid ID: ${id}`);

          testCount++;
          if (testCount === validIds.length) {
            server.close();
            t.end();
          }
        }).on('error', (err) => {
          t.fail(`Request failed: ${err.message}`);
          server.close();
          t.end();
        });
      });
    });
  });

  t.test('should not execute shell commands from ID parameter', (t) => {
    const maliciousIds = [
      '; touch /tmp/hacked.txt;',
      '| echo vulnerable > /tmp/test.txt',
      '$(echo pwned)',
      '`id`',
      '& echo shell-injection &',
    ];

    let testCount = 0;
    const app = createTestApp();
    const server = app.listen(0, () => {
      const port = server.address().port;

      maliciousIds.forEach((id) => {
        const encodedId = encodeURIComponent(id);
        http.get(`http://localhost:${port}/edit/${encodedId}`, (res) => {
          t.equal(res.statusCode, 400, `Should block command injection: "${id}"`);

          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            // Verify the malicious command was not executed
            t.notMatch(data, /pwned|hacked|vulnerable/,
              `Should not show evidence of command execution for: "${id}"`);
            testCount++;
            if (testCount === maliciousIds.length) {
              server.close();
              t.end();
            }
          });
        }).on('error', (err) => {
          t.fail(`Request failed: ${err.message}`);
          server.close();
          t.end();
        });
      });
    });
  });

  t.test('should validate ID early in the request lifecycle', (t) => {
    // Test that validation happens before any database queries
    const invalidId = '../../../etc/passwd';
    const app = createTestApp();
    const server = app.listen(0, () => {
      const port = server.address().port;
      const encodedId = encodeURIComponent(invalidId);

      const startTime = Date.now();
      http.get(`http://localhost:${port}/edit/${encodedId}`, (res) => {
        const responseTime = Date.now() - startTime;

        t.equal(res.statusCode, 400, 'Should reject invalid ID');
        // Validation should be fast (< 100ms) as it doesn't hit the database
        t.ok(responseTime < 100, 'Validation should be fast (early in request lifecycle)');

        server.close();
        t.end();
      }).on('error', (err) => {
        t.fail(`Request failed: ${err.message}`);
        server.close();
        t.end();
      });
    });
  });

  t.end();
});

tap.test('Edit route - Functional correctness', (t) => {

  t.test('should preserve functionality for valid ObjectIDs', (t) => {
    // Ensure the security fix doesn't break legitimate use cases
    const validId = '507f1f77bcf86cd799439011';
    const app = createTestApp();
    const server = app.listen(0, () => {
      const port = server.address().port;

      http.get(`http://localhost:${port}/edit/${validId}`, (res) => {
        // Should attempt to process (may fail with DB error, but shouldn't be 400)
        t.notEqual(res.statusCode, 400, 'Should not reject valid ObjectID');

        server.close();
        t.end();
      }).on('error', (err) => {
        t.fail(`Request failed: ${err.message}`);
        server.close();
        t.end();
      });
    });
  });

  t.test('should handle case-insensitive hex characters', (t) => {
    // MongoDB ObjectIDs can be uppercase or lowercase hex
    const mixedCaseIds = [
      '507f1F77BCF86cd799439011',
      'AaBbCcDdEeFf001122334455',
    ];

    let testCount = 0;
    const app = createTestApp();
    const server = app.listen(0, () => {
      const port = server.address().port;

      mixedCaseIds.forEach((id) => {
        http.get(`http://localhost:${port}/edit/${id}`, (res) => {
          t.notEqual(res.statusCode, 400, `Should accept mixed case hex: ${id}`);

          testCount++;
          if (testCount === mixedCaseIds.length) {
            server.close();
            t.end();
          }
        }).on('error', (err) => {
          t.fail(`Request failed: ${err.message}`);
          server.close();
          t.end();
        });
      });
    });
  });

  t.end();
});

// Helper function to create a minimal Express app for testing
function createTestApp() {
  const app = express();
  const bodyParser = require('body-parser');

  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: false }));

  // Mock the current_user middleware
  app.use((req, res, next) => next());

  // Set up a mock view engine to prevent errors when rendering
  app.set('view engine', 'ejs');
  app.set('views', __dirname + '/../views');

  // Override res.render to prevent actual rendering in tests
  const originalRender = app.response.render;
  app.response.render = function(view, options, callback) {
    // Instead of rendering, just send a success response
    this.status(200).send(`Mock render: ${view}`);
  };

  // Add the route we're testing
  app.get('/edit/:id', routes.edit);

  return app;
}
